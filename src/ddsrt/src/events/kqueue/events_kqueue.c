/*
 * Copyright(c) 2020 ADLINK Technology Limited and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v. 1.0 which is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "dds/ddsrt/events/kqueue.h"
#include "dds/ddsrt/events.h"
#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/sync.h"
#include "dds/ddsrt/log.h"
#ifndef NDEBUG
#include "dds/ddsrt/threads.h"
#endif

#define EVENTS_CONTAINER_DELTA 8

typedef enum event_status {
  EVENT_STATUS_UNREGISTERED,
  EVENT_STATUS_REGISTERED,
  EVENT_STATUS_DEREGISTERED,
  EVENT_STATUS_INTERNAL
} event_status_t;

struct queued_event {
  ddsrt_event_t *external;
  event_status_t status;
  union {
    int fd;
    int nextfree;
  } u;
};

typedef struct queued_event queued_event_t;

 /**
 * @brief kevent (Apple & FreeBSD) implementation of ddsrt_event_queue.
 *
 * This implementation uses a kqueue for monitoring a set of filedescriptors for events.
 * Using the kevent call, the kernel can be told to add/modify fd's on its list for monitoring
 * or to wait for events on the monitored fd's. Interrupts of waits are done through writes
 * to an internal pipe.
 */
struct ddsrt_event_queue {
  int kq;                    /**< kevent polling instance (constant)*/

  /* only one thread waits/iterates over the result, so these may be used unlocked */
  size_t ievents;            /**< current iterator for getting the next triggered event*/
  size_t kevents_count;      /**< number of events in kevents */
  struct kevent* kevents;    /**< array which kevent uses to write back to, has identical size as this->events*/

  queued_event_t *events;    /**< container for stored events*/
  size_t nevents;            /**< number of events stored*/
  size_t cevents;            /**< capacity of events stored*/
  ddsrt_event_t **newevents; /**< container for modified events*/
  size_t nnewevents;         /**< number of new events added since last call to wait function*/
  size_t cnewevents;         /**< capacity for new events*/
  int events_freelist_head;

  ddsrt_mutex_t lock;        /**< for keeping adds/deletes from occurring simultaneously */
  int interrupt[2];          /**< pipe for interrupting waits, trigger updates to kqueue */
  ddsrt_event_t interrupt_evt;

#ifndef NDEBUG
  // only the owning thread may call wait/next_event, set on the first call to wait()
  bool owning_thread_set;
  ddsrt_thread_t owning_thread;
#endif
};

/**
* @brief Initializes an event queue.
*
* Will set the counters to 0 and create the containers for triggers and kevents.
* Will create a kevent kernel event instance and open the interrupt pipe.
*
* @param[in,out] queue The queue to initialize.
*
* @retval DDS_RETCODE_OK
*             The queue was initialized succesfully.
* @retval DDS_RETCODE_ERROR
*             - There was an issue with reserving memory for the (k)event queue.
*             - Kevent instance or interrupt pipe could not be initialized correctly.
*/
static dds_return_t ddsrt_event_queue_init(ddsrt_event_queue_t* queue) ddsrt_nonnull_all;

static int16_t kevent_filter_from_event(const struct ddsrt_event *ev)
{
  assert (ev->flags == DDSRT_EVENT_FLAG_READ); // being lazy
  return EVFILT_READ;
}

static dds_return_t ddsrt_event_queue_init(ddsrt_event_queue_t* queue)
{
  queue->nevents = 0;
  queue->cevents = EVENTS_CONTAINER_DELTA;
  queue->ievents = SIZE_MAX;
  queue->kevents_count = 0;
  queue->nnewevents = 0;
  queue->cnewevents = EVENTS_CONTAINER_DELTA;

  /*create kevents array*/
  queue->kevents = ddsrt_malloc(sizeof(*queue->kevents) * queue->cevents);
  if (NULL == queue->kevents)
    goto alloc_fail_0;
  queue->events = ddsrt_malloc(sizeof(*queue->events) * queue->cevents);
  if (NULL == queue->events)
    goto alloc_fail_1;
  queue->newevents = ddsrt_malloc(sizeof(*queue->newevents) * queue->cnewevents);
  if (NULL == queue->newevents)
    goto alloc_fail_2;

  /*create kevent polling instance */
  if (-1 == (queue->kq = kqueue()))
    goto kq_fail;
  else if (-1 == fcntl(queue->kq, F_SETFD, fcntl(queue->kq, F_GETFD) | FD_CLOEXEC))
    goto pipe0_fail;
  /*create interrupt pipe */
  else if (-1 == pipe(queue->interrupt))
    goto pipe0_fail;
  else if (-1 == fcntl(queue->interrupt[0], F_SETFD, fcntl(queue->interrupt[0], F_GETFD) | FD_CLOEXEC) ||
           -1 == fcntl(queue->interrupt[1], F_SETFD, fcntl(queue->interrupt[1], F_GETFD) | FD_CLOEXEC) ||
           -1 == fcntl(queue->interrupt[0], F_SETFL, O_NONBLOCK))
    goto pipe1_fail;

#ifndef NDEBUG
  queue->owning_thread_set = false;
  memset (&queue->owning_thread, 0, sizeof (queue->owning_thread));
#endif

  {
    struct ddsrt_event * const ev = &queue->interrupt_evt;
    ev->type = DDSRT_EVENT_TYPE_INTERNAL;
    ev->flags = DDSRT_EVENT_FLAG_READ;
    ddsrt_atomic_st32(&ev->triggered, DDSRT_EVENT_FLAG_UNSET);
    ev->parent = queue;
  }

  {
    assert(queue->nevents < queue->cevents);
    queued_event_t * const qe = &queue->events[queue->nevents];
    const uintptr_t idx = (uintptr_t) (qe - queue->events);
    qe->external = &queue->interrupt_evt;
    qe->status = EVENT_STATUS_INTERNAL;
    qe->u.fd = queue->interrupt[0];
    struct kevent ke;
    EV_SET(&ke, qe->u.fd, kevent_filter_from_event(&queue->interrupt_evt), EV_ADD, 0, 0, (void *) idx);
    queue->nevents++;
    if (-1 == kevent(queue->kq, &ke, 1, NULL, 0, NULL))
      goto pipe1_fail;
  }

  queue->events_freelist_head = -1;
  ddsrt_mutex_init(&queue->lock);
  return DDS_RETCODE_OK;

pipe1_fail:
  close(queue->interrupt[0]);
  close(queue->interrupt[1]);
pipe0_fail:
  close(queue->kq);
kq_fail:
  ddsrt_free(queue->newevents);
alloc_fail_2:
  ddsrt_free(queue->events);
alloc_fail_1:
  ddsrt_free(queue->kevents);
alloc_fail_0:
  return DDS_RETCODE_ERROR;
}

/**
* @brief Finishes an event queue.
*
* Will free created containers and close interrupt pipe and kernel event monitor.
*
* @param[in,out] queue The queue to finish.
*/
static void ddsrt_event_queue_fini(ddsrt_event_queue_t* queue) ddsrt_nonnull_all;

static void ddsrt_event_queue_fini(ddsrt_event_queue_t* queue)
{
  close(queue->interrupt[0]);
  close(queue->interrupt[1]);
  close(queue->kq);

  ddsrt_mutex_destroy(&queue->lock);
  ddsrt_free(queue->events);
  ddsrt_free(queue->kevents);
  ddsrt_free(queue->newevents);
}

ddsrt_event_queue_t* ddsrt_event_queue_create(void)
{
  ddsrt_event_queue_t* returnptr = ddsrt_malloc(sizeof(ddsrt_event_queue_t));
  if (DDS_RETCODE_OK != ddsrt_event_queue_init(returnptr)) {
    ddsrt_free(returnptr);
    returnptr = NULL;
  }
  return returnptr;
}

void ddsrt_event_queue_delete(ddsrt_event_queue_t* queue)
{
  ddsrt_event_queue_fini(queue);
  ddsrt_free(queue);
}

dds_return_t ddsrt_event_queue_wait(ddsrt_event_queue_t* queue, dds_duration_t reltime)
{
  dds_return_t ret = DDS_RETCODE_OK;

#ifndef NDEBUG
  // Only one thread may call wait/next, and that thread is also the only
  // one may touch ievents/kevents_count or update the kqueue.  The first
  // call to wait sets the thread id.
  ddsrt_mutex_lock (&queue->lock);
  if (queue->owning_thread_set)
    assert(ddsrt_thread_equal(queue->owning_thread, ddsrt_thread_self()));
  else
  {
    queue->owning_thread = ddsrt_thread_self();
    queue->owning_thread_set = true;
  }
  ddsrt_mutex_unlock (&queue->lock);
#endif

  assert(DDS_DURATION_INVALID != reltime);
  struct timespec tmout, *ptmout = NULL;
  if (DDS_INFINITY != reltime)
  {
    tmout.tv_sec = reltime / DDS_NSECS_IN_SEC;
    tmout.tv_nsec = reltime % DDS_NSECS_IN_SEC;
    ptmout = &tmout;
  }

  int nevs = kevent(queue->kq, NULL, 0, queue->kevents, (int)queue->nevents, ptmout);
  printf ("nevs %d in %d errno %d ptmout %p tmout %d,%d\n", nevs, (int)queue->nevents, errno, ptmout, (int)tmout.tv_sec, (int)tmout.tv_nsec);
  if (nevs < 0)
    ret = DDS_RETCODE_ERROR;

  queue->ievents = 0;
  queue->kevents_count = (size_t) nevs;
  return ret;
}

void ddsrt_event_queue_add(ddsrt_event_queue_t* queue, ddsrt_event_t* evt)
{
  ddsrt_mutex_lock(&queue->lock);

  if (queue->nnewevents == queue->cnewevents)
  {
    queue->cnewevents += EVENTS_CONTAINER_DELTA;
    queue->newevents = ddsrt_realloc(queue->newevents, sizeof(*queue->newevents) * queue->cnewevents);
  }

  queue->newevents[queue->nnewevents++] = evt;
  ddsrt_mutex_unlock(&queue->lock);
  ddsrt_event_queue_signal(queue);
}

void ddsrt_event_queue_clear(ddsrt_event_queue_t* queue)
{
  ddsrt_mutex_lock(&queue->lock);

  for (size_t i = 0; i < queue->nevents; i++)
  {
    if (queue->events[i].status == EVENT_STATUS_REGISTERED)
      queue->events[i].status = EVENT_STATUS_DEREGISTERED;
  }

  queue->nnewevents = 0;
  ddsrt_mutex_unlock(&queue->lock);
  ddsrt_event_queue_signal(queue);
}

dds_return_t ddsrt_event_queue_signal(ddsrt_event_queue_t* queue)
{
  char buf = 0x0;
  if (1 != write(queue->interrupt[1], &buf, 1))
    return DDS_RETCODE_ERROR;
  return DDS_RETCODE_OK;
}

dds_return_t ddsrt_event_queue_remove(ddsrt_event_queue_t* queue, ddsrt_event_t* evt)
{
  dds_return_t ret = DDS_RETCODE_ALREADY_DELETED;
  ddsrt_mutex_lock(&queue->lock);

  /*check registered events*/
  for (size_t i = 0; i < queue->nevents; i++)
  {
    queued_event_t* qe = &queue->events[i];
    if (qe->status == EVENT_STATUS_REGISTERED && qe->external == evt)
    {
      qe->status = EVENT_STATUS_DEREGISTERED;
      ret = DDS_RETCODE_OK;
      break;
    }
  }

  /*check not yet registered events*/
  for (size_t i = 0; i < queue->nnewevents; i++)
  {
    if (queue->newevents[i] == evt)
    {
      queue->newevents[i] = queue->newevents[--queue->nnewevents];
      ret = DDS_RETCODE_OK;
      break;
    }
  }

  ddsrt_mutex_unlock(&queue->lock);
  ddsrt_event_queue_signal(queue);
  return ret;
}

static queued_event_t *get_unused_event_slot(ddsrt_event_queue_t* queue)
{
  assert (queue->nevents < queue->cevents);
  if (queue->events_freelist_head < 0)
  {
    return &queue->events[queue->nevents++];
  }
  else
  {
    const int idx = queue->events_freelist_head;
    queued_event_t * const qe = &queue->events[idx];
    assert (qe->status == EVENT_STATUS_UNREGISTERED);
    queue->events_freelist_head = qe->u.nextfree;
    queue->nevents++;
    return qe;
  }
}

static void ddsrt_event_queue_update(ddsrt_event_queue_t* queue)
{
  ddsrt_mutex_lock (&queue->lock);

  /*remove deregistered events*/
  {
    size_t i = 0;
    while (i < queue->nevents)
    {
      queued_event_t* qe = &(queue->events[i]);
      if (EVENT_STATUS_DEREGISTERED != qe->status)
        i++;
      else
      {
        struct kevent ke;
        EV_SET(&ke, qe->u.fd, EVFILT_READ, EV_DELETE, 0, 0, 0);
        int result = kevent(queue->kq, &ke, 1, NULL, 0, NULL);
        assert(result != -1);
        (void) result;
        qe->status = EVENT_STATUS_UNREGISTERED;
        qe->u.nextfree = queue->events_freelist_head;
        queue->events_freelist_head = (int) (qe - queue->events);
        --queue->nevents;
      }
    }
  }

  /*resize queue->events & queue->kevents*/
  if (queue->cevents < queue->nevents + queue->nnewevents)
  {
    queue->cevents = queue->nevents + queue->nnewevents + EVENTS_CONTAINER_DELTA;
    queue->events = ddsrt_realloc(queue->events, sizeof(queued_event_t) * queue->cevents);
    queue->kevents = ddsrt_realloc(queue->kevents, sizeof(struct kevent) * queue->cevents);
  }

  /*register/modify events to kevent*/
  for (size_t i = 0; i < queue->nnewevents; i++)
  {
    queued_event_t * const qe = get_unused_event_slot(queue);
    const uintptr_t idx = (uintptr_t) (qe - queue->events);
    struct kevent ke;
    qe->external = queue->newevents[i];
    switch (qe->external->type)
    {
      case DDSRT_EVENT_TYPE_SOCKET:
        qe->u.fd = qe->external->u.socket.sock;
        break;
      case DDSRT_EVENT_TYPE_UNSET:
      case DDSRT_EVENT_TYPE_INTERNAL:
        abort ();
        break;
    }
    EV_SET(&ke, qe->u.fd, kevent_filter_from_event(qe->external), EV_ADD, 0, 0, (void *) idx);
    qe->status = EVENT_STATUS_REGISTERED;
    int result = kevent(queue->kq, &ke, 1, NULL, 0, NULL);
    assert(result != -1);
    (void) result;
  }

  queue->ievents = SIZE_MAX;
  queue->kevents_count = 0;
  queue->nnewevents = 0;

  ddsrt_mutex_unlock(&queue->lock);
}

static void handle_trigger(ddsrt_event_queue_t* queue)
{
  char buf = 0x0;
  int n = (int)read(queue->interrupt[0], &buf, 1);
  if (1 != n && !(-1 == n && EAGAIN == errno))
  {
    DDS_WARNING("ddsrt_event_queue: read failed on trigger pipe\n");
    assert(0);
  }
  ddsrt_event_queue_update(queue);
}

ddsrt_event_t* ddsrt_event_queue_next(ddsrt_event_queue_t* queue)
{
#ifndef NDEBUG
  ddsrt_mutex_lock (&queue->lock);
  assert(queue->owning_thread_set && ddsrt_thread_equal(queue->owning_thread, ddsrt_thread_self()));
  ddsrt_mutex_unlock (&queue->lock);
#endif

  while (queue->ievents < queue->kevents_count)
  {
    struct kevent * const ke = &queue->kevents[queue->ievents++];
    queued_event_t * const qe = &queue->events[(uintptr_t) ke->udata];
    if (EVENT_STATUS_REGISTERED == qe->status)
      return qe->external;

    if (qe->external == &queue->interrupt_evt)
    {
      // Always update if triggered.  If anything changes because of it,
      // the iterator becomes invalid, but triggers and updates are rare
      // and it is all level-triggered, so just go back to waiting
      assert(qe->status == EVENT_STATUS_INTERNAL);
      printf("update\n");
      handle_trigger(queue);
      return NULL;
    }
  }
  return NULL;
}
