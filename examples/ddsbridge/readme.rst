..
   Copyright(c) 2026 ZettaScale Technology and others

   This program and the accompanying materials are made available under the
   terms of the Eclipse Public License v. 2.0 which is available at
   http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
   v. 1.0 which is available at
   http://www.eclipse.org/org/documents/edl-v10.php.

   SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

DDS bridge
==========

This example is the first skeleton of a bidirectional bridge between two DDS
domains.  It creates one participant in each domain, creates readers for the
``DCPSPublication`` and ``DCPSSubscription`` built-in topics in each participant,
and uses a library-owned waitset to dispatch discovery events from both domains.

Run it with two domain ids:

.. code-block:: console

   ddsbridge 0 1

The callbacks currently drain the built-in endpoint samples and report where the
future mirroring work will be done.  Later steps can use the publication and
subscription discovery data to create mirrored readers and writers for each
application topic.
