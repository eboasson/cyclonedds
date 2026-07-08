// Copyright(c) 2026 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include "idl/heap.h"
#include "idl/processor.h"
#include "idl/string.h"

#include "directive.h"
#include "parser_impl.h"
#include "parser.h"
#include "scanner.h"
#include "scope.h"
#include "symbol.h"
#include "tree.h"

typedef struct idl_parser_stream {
  idl_pstate_t *pstate;
  idl_token_t token;
  bool have_token;
} idl_parser_stream_t;

static bool
token_has_owned_string(const idl_token_t *token)
{
  switch (token->code) {
    case IDL_TOKEN_IDENTIFIER:
    case IDL_TOKEN_STRING_LITERAL:
    case IDL_TOKEN_PP_NUMBER:
    case IDL_TOKEN_COMMENT:
    case IDL_TOKEN_LINE_COMMENT:
      return token->value.str != NULL;
    default:
      return false;
  }
}

static void
token_fini(idl_token_t *token)
{
  if (token_has_owned_string(token))
    idl_free(token->value.str);
  memset(token, 0, sizeof(*token));
}

static void
stream_init(idl_parser_stream_t *stream, idl_pstate_t *pstate)
{
  memset(stream, 0, sizeof(*stream));
  stream->pstate = pstate;
}

static void
stream_fini(idl_parser_stream_t *stream)
{
  if (stream->have_token)
    token_fini(&stream->token);
}

static idl_retcode_t
stream_advance(idl_parser_stream_t *stream)
{
  idl_pstate_t *pstate = stream->pstate;

  for (;;) {
    idl_retcode_t ret;

    if (stream->have_token)
      token_fini(&stream->token);

    ret = idl_scan(pstate, &stream->token);
    stream->have_token = true;
    if (ret < 0)
      return ret;

    if (stream->token.code == '\n') {
      pstate->scanner.state = IDL_SCAN;
      continue;
    }

    if (stream->token.code == IDL_TOKEN_COMMENT ||
        stream->token.code == IDL_TOKEN_LINE_COMMENT) {
      continue;
    }

    if ((unsigned)pstate->scanner.state & (unsigned)IDL_SCAN_DIRECTIVE) {
      ret = idl_parse_directive(pstate, &stream->token);
      if (stream->token.code == '\0' &&
          (ret == IDL_RETCODE_OK || ret == IDL_RETCODE_PUSH_MORE))
        return IDL_RETCODE_OK;
      if (ret != IDL_RETCODE_OK && ret != IDL_RETCODE_PUSH_MORE)
        return ret;
      continue;
    }

    return IDL_RETCODE_OK;
  }
}

static idl_location_t
location_span(idl_position_t first, idl_position_t last)
{
  idl_location_t location;
  location.first = first;
  location.last = last;
  return location;
}

static idl_retcode_t
syntax_error(idl_parser_stream_t *stream)
{
  idl_error(stream->pstate, &stream->token.location, "syntax error");
  return IDL_RETCODE_SYNTAX_ERROR;
}

static idl_retcode_t
expect(idl_parser_stream_t *stream, int32_t code, idl_location_t *location)
{
  if (stream->token.code != code)
    return syntax_error(stream);
  if (location)
    *location = stream->token.location;
  return stream_advance(stream);
}

static idl_retcode_t
parse_identifier(idl_parser_stream_t *stream, idl_name_t **namep)
{
  idl_pstate_t *pstate = stream->pstate;
  idl_name_t *name = NULL;
  char *identifier;
  size_t offset;
  bool nocase;
  idl_retcode_t ret;

  if (stream->token.code != IDL_TOKEN_IDENTIFIER)
    return syntax_error(stream);

  identifier = stream->token.value.str;
  nocase = (pstate->config.flags & IDL_FLAG_CASE_SENSITIVE) == 0;
  offset = (identifier[0] == '_');
  if (!offset && idl_iskeyword(pstate, identifier, nocase)) {
    idl_error(pstate, &stream->token.location,
      "Identifier '%s' collides with a keyword", identifier);
    return IDL_RETCODE_SEMANTIC_ERROR;
  }

  if (!(identifier = idl_strdup(stream->token.value.str + offset)))
    return IDL_RETCODE_NO_MEMORY;
  ret = idl_create_name(
    pstate, &stream->token.location, identifier, false, &name);
  if (ret != IDL_RETCODE_OK) {
    idl_free(identifier);
    return ret;
  }

  if ((ret = stream_advance(stream)) != IDL_RETCODE_OK) {
    idl_delete_name(name);
    return ret;
  }

  *namep = name;
  return IDL_RETCODE_OK;
}

static idl_retcode_t parse_definition(idl_parser_stream_t *stream, void **nodep);

static idl_retcode_t
parse_definitions(
  idl_parser_stream_t *stream,
  int32_t stop_code,
  bool allow_empty,
  void **nodep)
{
  void *nodes = NULL;
  idl_retcode_t ret;

  while (stream->token.code != stop_code) {
    void *node = NULL;

    if (stream->token.code == '\0') {
      if (stop_code == '\0')
        break;
      ret = syntax_error(stream);
      goto err;
    }

    if ((ret = parse_definition(stream, &node)) != IDL_RETCODE_OK)
      goto err;
    nodes = idl_push_node(nodes, node);
  }

  if (!nodes && !allow_empty) {
    ret = syntax_error(stream);
    goto err;
  }

  *nodep = nodes;
  return IDL_RETCODE_OK;
err:
  idl_delete_node(nodes);
  return ret;
}

static idl_retcode_t
parse_struct(idl_parser_stream_t *stream, void **nodep)
{
  idl_pstate_t *pstate = stream->pstate;
  idl_position_t first = stream->token.location.first;
  idl_location_t location;
  idl_location_t rbrace_location;
  idl_struct_t *strct = NULL;
  idl_name_t *name = NULL;
  bool entered_scope = false;
  idl_retcode_t ret;

  assert(stream->token.code == IDL_TOKEN_STRUCT);
  if ((ret = stream_advance(stream)) != IDL_RETCODE_OK)
    return ret;
  if ((ret = parse_identifier(stream, &name)) != IDL_RETCODE_OK)
    return ret;

  location = location_span(first, name->symbol.location.last);
  ret = idl_create_struct(pstate, &location, name, NULL, &strct);
  if (ret != IDL_RETCODE_OK) {
    idl_delete_name(name);
    return ret;
  }
  name = NULL;
  entered_scope = true;

  if ((ret = expect(stream, '{', NULL)) != IDL_RETCODE_OK)
    goto err;
  if ((ret = expect(stream, '}', &rbrace_location)) != IDL_RETCODE_OK)
    goto err;

  location = location_span(first, rbrace_location.last);
  if ((ret = idl_finalize_struct(
        pstate, &location, strct, NULL)) != IDL_RETCODE_OK)
    goto err;
  entered_scope = false;

  *nodep = strct;
  return IDL_RETCODE_OK;
err:
  if (entered_scope)
    idl_exit_scope(pstate);
  idl_delete_node(strct);
  return ret;
}

static idl_retcode_t
parse_module(idl_parser_stream_t *stream, void **nodep)
{
  idl_pstate_t *pstate = stream->pstate;
  idl_position_t first = stream->token.location.first;
  idl_location_t location;
  idl_location_t rbrace_location;
  idl_module_t *module = NULL;
  idl_name_t *name = NULL;
  void *definitions = NULL;
  bool entered_scope = false;
  idl_retcode_t ret;

  assert(stream->token.code == IDL_TOKEN_MODULE);
  if ((ret = stream_advance(stream)) != IDL_RETCODE_OK)
    return ret;
  if ((ret = parse_identifier(stream, &name)) != IDL_RETCODE_OK)
    return ret;

  location = location_span(first, name->symbol.location.last);
  ret = idl_create_module(pstate, &location, name, &module);
  if (ret != IDL_RETCODE_OK) {
    idl_delete_name(name);
    return ret;
  }
  name = NULL;
  entered_scope = true;

  if ((ret = expect(stream, '{', NULL)) != IDL_RETCODE_OK)
    goto err;
  if ((ret = parse_definitions(
        stream, '}', false, &definitions)) != IDL_RETCODE_OK)
    goto err;
  if ((ret = expect(stream, '}', &rbrace_location)) != IDL_RETCODE_OK)
    goto err;

  location = location_span(first, rbrace_location.last);
  if ((ret = idl_finalize_module(
        pstate, &location, module, definitions)) != IDL_RETCODE_OK)
    goto err;
  entered_scope = false;
  definitions = NULL;

  *nodep = module;
  return IDL_RETCODE_OK;
err:
  if (entered_scope)
    idl_exit_scope(pstate);
  idl_delete_node(definitions);
  idl_delete_node(module);
  return ret;
}

static idl_retcode_t
parse_definition(idl_parser_stream_t *stream, void **nodep)
{
  void *node = NULL;
  idl_retcode_t ret;

  switch (stream->token.code) {
    case IDL_TOKEN_MODULE:
      ret = parse_module(stream, &node);
      break;
    case IDL_TOKEN_STRUCT:
      ret = parse_struct(stream, &node);
      break;
    default:
      return syntax_error(stream);
  }

  if (ret != IDL_RETCODE_OK)
    return ret;
  if ((ret = expect(stream, ';', NULL)) != IDL_RETCODE_OK) {
    idl_delete_node(node);
    return ret;
  }

  *nodep = node;
  return IDL_RETCODE_OK;
}

static idl_retcode_t
parse_specification(idl_parser_stream_t *stream)
{
  idl_pstate_t *pstate = stream->pstate;
  void *definitions = NULL;
  idl_retcode_t ret;

  if ((ret = parse_definitions(
        stream, '\0', true, &definitions)) != IDL_RETCODE_OK)
    return ret;

  if (definitions) {
    pstate->root = pstate->root ?
      idl_push_node(pstate->root, definitions) : definitions;
    return IDL_RETCODE_OK;
  }

  if (!pstate->root)
    pstate->root = NULL;
  return IDL_RETCODE_OK;
}

idl_retcode_t
idl_parse_hand_written(idl_pstate_t *pstate)
{
  idl_parser_stream_t stream;
  idl_retcode_t ret = IDL_RETCODE_OK;

  assert(pstate);
  stream_init(&stream, pstate);

  if ((ret = stream_advance(&stream)) == IDL_RETCODE_OK)
    ret = parse_specification(&stream);

  stream_fini(&stream);
  return ret;
}
