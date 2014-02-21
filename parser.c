/*
Copyright (c) 2013. The YARA Authors. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stddef.h>
#include <string.h>

#include "ahocorasick.h"
#include "atoms.h"
#include "exec.h"
#include "hash.h"
#include "mem.h"
#include "parser.h"
#include "re.h"
#include "utils.h"


#define todigit(x)  ((x) >='A'&& (x) <='F')? \
                    ((uint8_t) (x - 'A' + 10)) : \
                    ((uint8_t) (x - '0'))


int yr_parser_emit(
    yyscan_t yyscanner,
    int8_t instruction,
    int8_t** instruction_address)
{
  return yr_arena_write_data(
      yyget_extra(yyscanner)->code_arena,
      &instruction,
      sizeof(int8_t),
      (void**) instruction_address);
}


int yr_parser_emit_with_arg(
    yyscan_t yyscanner,
    int8_t instruction,
    int64_t argument,
    int8_t** instruction_address)
{
  int result = yr_arena_write_data(
      yyget_extra(yyscanner)->code_arena,
      &instruction,
      sizeof(int8_t),
      (void**) instruction_address);

  if (result == ERROR_SUCCESS)
    result = yr_arena_write_data(
        yyget_extra(yyscanner)->code_arena,
        &argument,
        sizeof(int64_t),
        NULL);

  return result;
}


int yr_parser_emit_with_arg_reloc(
    yyscan_t yyscanner,
    int8_t instruction,
    int64_t argument,
    int8_t** instruction_address)
{
  void* ptr;

  int result = yr_arena_write_data(
      yyget_extra(yyscanner)->code_arena,
      &instruction,
      sizeof(int8_t),
      (void**) instruction_address);

  if (result == ERROR_SUCCESS)
    result = yr_arena_write_data(
        yyget_extra(yyscanner)->code_arena,
        &argument,
        sizeof(int64_t),
        &ptr);

  if (result == ERROR_SUCCESS)
    result = yr_arena_make_relocatable(
        yyget_extra(yyscanner)->code_arena,
        ptr,
        0,
        EOL);

  return result;
}


void yr_parser_emit_pushes_for_strings(
    yyscan_t yyscanner,
    const char* identifier)
{
  YR_COMPILER* compiler = yyget_extra(yyscanner);
  YR_STRING* string = compiler->current_rule_strings;
  const char* string_identifier;
  const char* target_identifier;

  while(!STRING_IS_NULL(string))
  {
    // Don't generate pushes for strings chained to another one, we are
    // only interested in non-chained strings or the head of the chain.

    if (string->chained_to == NULL)
    {
      string_identifier = string->identifier;
      target_identifier = identifier;

      while (*target_identifier != '\0' &&
             *string_identifier != '\0' &&
             *target_identifier == *string_identifier)
      {
        target_identifier++;
        string_identifier++;
      }

      if ((*target_identifier == '\0' && *string_identifier == '\0') ||
           *target_identifier == '*')
      {
        yr_parser_emit_with_arg_reloc(
            yyscanner,
            PUSH,
            PTR_TO_UINT64(string),
            NULL);

        string->g_flags |= STRING_GFLAGS_REFERENCED;
      }
    }

    string = yr_arena_next_address(
        compiler->strings_arena,
        string,
        sizeof(YR_STRING));
  }
}


YR_STRING* yr_parser_lookup_string(
    yyscan_t yyscanner,
    const char* identifier)
{
  YR_STRING* string;
  YR_COMPILER* compiler = yyget_extra(yyscanner);

  string = compiler->current_rule_strings;

  while(!STRING_IS_NULL(string))
  {
    // If some string $a gets fragmented into multiple chained
    // strings, all those fragments have the same $a identifier
    // but we are interested in the heading fragment, which is
    // that with chained_to == NULL

    if (strcmp(string->identifier, identifier) == 0 &&
        string->chained_to == NULL)
    {
      return string;
    }

    string = yr_arena_next_address(
        compiler->strings_arena,
        string,
        sizeof(YR_STRING));
  }

  yr_compiler_set_error_extra_info(compiler, identifier);
  compiler->last_result = ERROR_UNDEFINED_STRING;

  return NULL;
}


YR_EXTERNAL_VARIABLE* yr_parser_lookup_external_variable(
    yyscan_t yyscanner,
    const char* identifier)
{
  YR_EXTERNAL_VARIABLE* external;
  YR_COMPILER* compiler = yyget_extra(yyscanner);
  int i;

  external = (YR_EXTERNAL_VARIABLE*) yr_arena_base_address(
      compiler->externals_arena);

  for (i = 0; i < compiler->externals_count; i++)
  {
    if (strcmp(external->identifier, identifier) == 0)
      return external;

    external = yr_arena_next_address(
        compiler->externals_arena,
        external,
        sizeof(YR_EXTERNAL_VARIABLE));
  }

  yr_compiler_set_error_extra_info(compiler, identifier);
  compiler->last_result = ERROR_UNDEFINED_IDENTIFIER;

  return NULL;
}


int _yr_parser_write_string(
    const char* identifier,
    int flags,
    YR_COMPILER* compiler,
    SIZED_STRING* str,
    RE* re,
    YR_STRING** string,
    int* min_atom_length)
{
  SIZED_STRING* literal_string;
  YR_AC_MATCH* new_match;

  YR_ATOM_LIST_ITEM* atom;
  YR_ATOM_LIST_ITEM* atom_list = NULL;

  int result;
  int max_string_len;
  int free_literal = FALSE;

  *string = NULL;

  result = yr_arena_allocate_struct(
      compiler->strings_arena,
      sizeof(YR_STRING),
      (void**) string,
      offsetof(YR_STRING, identifier),
      offsetof(YR_STRING, string),
      offsetof(YR_STRING, chained_to),
      EOL);

  if (result != ERROR_SUCCESS)
    return result;

  result = yr_arena_write_string(
      compiler->sz_arena,
      identifier,
      &(*string)->identifier);

  if (result != ERROR_SUCCESS)
    return result;

  if (flags & STRING_GFLAGS_HEXADECIMAL ||
      flags & STRING_GFLAGS_REGEXP)
  {
    literal_string = yr_re_extract_literal(re);

    if (literal_string != NULL)
    {
      flags |= STRING_GFLAGS_LITERAL;
      free_literal = TRUE;
    }
  }
  else
  {
    literal_string = str;
    flags |= STRING_GFLAGS_LITERAL;
  }

  (*string)->g_flags = flags;
  (*string)->chained_to = NULL;

  memset((*string)->matches, 0,
         sizeof((*string)->matches));

  memset((*string)->unconfirmed_matches, 0,
         sizeof((*string)->unconfirmed_matches));

  if (flags & STRING_GFLAGS_LITERAL)
  {
    (*string)->length = literal_string->length;

    result = yr_arena_write_data(
        compiler->sz_arena,
        literal_string->c_string,
        literal_string->length,
        (void*) &(*string)->string);

    if (result == ERROR_SUCCESS)
    {
      result = yr_atoms_extract_from_string(
          (uint8_t*) literal_string->c_string,
          literal_string->length,
          flags,
          &atom_list);
    }
  }
  else
  {
    result = yr_re_emit_code(re, compiler->re_code_arena);

    if (result == ERROR_SUCCESS)
      result = yr_atoms_extract_from_re(re, flags, &atom_list);
  }

  if (result == ERROR_SUCCESS)
  {
    // Add the string to Aho-Corasick automaton.

    if (atom_list != NULL)
    {
      result = yr_ac_add_string(
          compiler->automaton_arena,
          compiler->automaton,
          *string,
          atom_list);
    }
    else
    {
      result = yr_arena_allocate_struct(
          compiler->automaton_arena,
          sizeof(YR_AC_MATCH),
          (void**) &new_match,
          offsetof(YR_AC_MATCH, string),
          offsetof(YR_AC_MATCH, forward_code),
          offsetof(YR_AC_MATCH, backward_code),
          offsetof(YR_AC_MATCH, next),
          EOL);

      if (result == ERROR_SUCCESS)
      {
        new_match->backtrack = 0;
        new_match->string = *string;
        new_match->forward_code = re->root_node->forward_code;
        new_match->backward_code = NULL;
        new_match->next = compiler->automaton->root->matches;
        compiler->automaton->root->matches = new_match;
      }
    }
  }

  atom = atom_list;

  if (atom != NULL)
    *min_atom_length = MAX_ATOM_LENGTH;
  else
    *min_atom_length = 0;

  while (atom != NULL)
  {
    if (atom->atom_length < *min_atom_length)
      *min_atom_length = atom->atom_length;
    atom = atom->next;
  }

  if (flags & STRING_GFLAGS_LITERAL)
  {
    if (flags & STRING_GFLAGS_WIDE)
      max_string_len = (*string)->length * 2;
    else
      max_string_len = (*string)->length;

    if (max_string_len == *min_atom_length)
      (*string)->g_flags |= STRING_GFLAGS_FITS_IN_ATOM;
  }

  if (free_literal)
    yr_free(literal_string);

  if (atom_list != NULL)
    yr_atoms_list_destroy(atom_list);

  return result;
}

#include <stdint.h>
#include <limits.h>


YR_STRING* yr_parser_reduce_string_declaration(
    yyscan_t yyscanner,
    int32_t flags,
    const char* identifier,
    SIZED_STRING* str)
{
  int min_atom_length;
  int min_atom_length_aux;

  int32_t min_gap;
  int32_t max_gap;

  char* file_name;
  char message[512];

  YR_COMPILER* compiler = yyget_extra(yyscanner);
  YR_STRING* string = NULL;
  YR_STRING* aux_string;
  YR_STRING* prev_string;

  RE* re = NULL;
  RE* remainder_re;

  if (strcmp(identifier,"$") == 0)
    flags |= STRING_GFLAGS_ANONYMOUS;

  if (!(flags & STRING_GFLAGS_WIDE))
    flags |= STRING_GFLAGS_ASCII;

  if (str->flags & SIZED_STRING_FLAGS_NO_CASE)
    flags |= STRING_GFLAGS_NO_CASE;

  if (str->flags & SIZED_STRING_FLAGS_DOT_ALL)
    flags |= STRING_GFLAGS_REGEXP_DOT_ALL;

  // The STRING_GFLAGS_SINGLE_MATCH flag indicates that finding
  // a single match for the string is enough. This is true in
  // most cases, except when the string count (#) and string offset (@)
  // operators are used. All strings are marked STRING_FLAGS_SINGLE_MATCH
  // initially, and unmarked later if required.

  flags |= STRING_GFLAGS_SINGLE_MATCH;

  if (flags & STRING_GFLAGS_HEXADECIMAL ||
      flags & STRING_GFLAGS_REGEXP)
  {
    if (flags & STRING_GFLAGS_HEXADECIMAL)
      compiler->last_result = yr_re_compile_hex(
          str->c_string, &re);
    else
      compiler->last_result = yr_re_compile(
          str->c_string, &re);

    if (compiler->last_result != ERROR_SUCCESS)
    {
      snprintf(
          message,
          sizeof(message),
          "invalid %s \"%s\": %s",
          (flags & STRING_GFLAGS_HEXADECIMAL) ?
              "hex string" : "regular expression",
          identifier,
          re->error_message);

      yr_compiler_set_error_extra_info(
          compiler, message);

      goto _exit;
    }

    if (re->flags & RE_FLAGS_FAST_HEX_REGEXP)
      flags |= STRING_GFLAGS_FAST_HEX_REGEXP;

    compiler->last_result = yr_re_split_at_chaining_point(
        re, &re, &remainder_re, &min_gap, &max_gap);

    if (compiler->last_result != ERROR_SUCCESS)
      goto _exit;

    compiler->last_result = _yr_parser_write_string(
        identifier,
        flags,
        compiler,
        NULL,
        re,
        &string,
        &min_atom_length);

    if (compiler->last_result != ERROR_SUCCESS)
      goto _exit;

    if (remainder_re != NULL)
    {
      string->g_flags |= STRING_GFLAGS_CHAIN_TAIL | STRING_GFLAGS_CHAIN_PART;
      string->chain_gap_min = min_gap;
      string->chain_gap_max = max_gap;
    }

    // Use "aux_string" from now on, we want to keep the value of "string"
    // because it will returned.

    aux_string = string;

    while (remainder_re != NULL)
    {
      // Destroy regexp pointed by 're' before yr_re_split_at_jmp
      // overwrites 're' with another value.

      yr_re_destroy(re);

      compiler->last_result = yr_re_split_at_chaining_point(
          remainder_re, &re, &remainder_re, &min_gap, &max_gap);

      if (compiler->last_result != ERROR_SUCCESS)
        goto _exit;

      prev_string = aux_string;

      compiler->last_result = _yr_parser_write_string(
          identifier,
          flags,
          compiler,
          NULL,
          re,
          &aux_string,
          &min_atom_length_aux);

      if (compiler->last_result != ERROR_SUCCESS)
        goto _exit;

      if (min_atom_length_aux < min_atom_length)
        min_atom_length = min_atom_length_aux;

      aux_string->g_flags |= STRING_GFLAGS_CHAIN_PART;
      aux_string->chain_gap_min = min_gap;
      aux_string->chain_gap_max = max_gap;

      prev_string->chained_to = aux_string;
    }
  }
  else
  {
    compiler->last_result = _yr_parser_write_string(
        identifier,
        flags,
        compiler,
        str,
        NULL,
        &string,
        &min_atom_length);

    if (compiler->last_result != ERROR_SUCCESS)
      goto _exit;
  }

  if (compiler->file_name_stack_ptr > 0)
    file_name = compiler->file_name_stack[compiler->file_name_stack_ptr - 1];
  else
    file_name = NULL;

  if (min_atom_length < 2 && compiler->error_report_function != NULL)
  {
    snprintf(
        message,
        sizeof(message),
        "%s is slowing down scanning%s",
        string->identifier,
        min_atom_length == 0 ? " (critical!)" : "");

    compiler->error_report_function(
        YARA_ERROR_LEVEL_WARNING,
        file_name,
        yyget_lineno(yyscanner),
        message);
  }

_exit:

  if (re != NULL)
    yr_re_destroy(re);

  if (compiler->last_result != ERROR_SUCCESS)
    return NULL;

  return string;
}


int yr_parser_reduce_rule_declaration(
    yyscan_t yyscanner,
    int32_t flags,
    const char* identifier,
    char* tags,
    YR_STRING* strings,
    YR_META* metas)
{
  YR_COMPILER* compiler = yyget_extra(yyscanner);
  YR_RULE* rule;
  YR_STRING* string;

  if (yr_hash_table_lookup(
        compiler->rules_table,
        identifier,
        compiler->current_namespace->name) != NULL)
  {
    // A rule with the same identifier already exists, return the
    // appropriate error.

    yr_compiler_set_error_extra_info(compiler, identifier);
    compiler->last_result = ERROR_DUPLICATE_RULE_IDENTIFIER;
    return compiler->last_result;
  }

  // Check for unreferenced (unused) strings.

  string = compiler->current_rule_strings;

  while(!STRING_IS_NULL(string))
  {
    // Only the heading fragment in a chain of strings (the one with
    // chained_to == NULL) must be referenced. All other fragments
    // are never marked as referenced.

    if (!STRING_IS_REFERENCED(string) &&
        string->chained_to == NULL)
    {
      yr_compiler_set_error_extra_info(compiler, string->identifier);
      compiler->last_result = ERROR_UNREFERENCED_STRING;
      break;
    }

    string = yr_arena_next_address(
        compiler->strings_arena,
        string,
        sizeof(YR_STRING));
  }

  if (compiler->last_result != ERROR_SUCCESS)
    return compiler->last_result;

  compiler->last_result = yr_arena_allocate_struct(
      compiler->rules_arena,
      sizeof(YR_RULE),
      (void**) &rule,
      offsetof(YR_RULE, identifier),
      offsetof(YR_RULE, tags),
      offsetof(YR_RULE, strings),
      offsetof(YR_RULE, metas),
      offsetof(YR_RULE, ns),
      EOL);

  if (compiler->last_result != ERROR_SUCCESS)
    return compiler->last_result;

  compiler->last_result = yr_arena_write_string(
      compiler->sz_arena,
      identifier,
      &rule->identifier);

  if (compiler->last_result != ERROR_SUCCESS)
    return compiler->last_result;

  compiler->last_result = yr_parser_emit_with_arg_reloc(
      yyscanner,
      RULE_POP,
      PTR_TO_UINT64(rule),
      NULL);

  if (compiler->last_result != ERROR_SUCCESS)
    return compiler->last_result;

  rule->g_flags = flags | compiler->current_rule_flags;
  rule->tags = tags;
  rule->strings = strings;
  rule->metas = metas;
  rule->ns = compiler->current_namespace;

  compiler->current_rule_flags = 0;
  compiler->current_rule_strings = NULL;

  yr_hash_table_add(
      compiler->rules_table,
      identifier,
      compiler->current_namespace->name,
      (void*) rule);

  return compiler->last_result;
}


int yr_parser_reduce_string_identifier(
    yyscan_t yyscanner,
    const char* identifier,
    int8_t instruction)
{
  YR_STRING* string;
  YR_COMPILER* compiler = yyget_extra(yyscanner);

  if (strcmp(identifier, "$") == 0)
  {
    if (compiler->loop_depth > 0)
    {
      yr_parser_emit_with_arg(
          yyscanner,
          PUSH_M,
          LOOP_LOCAL_VARS * (compiler->loop_depth - 1),
          NULL);

      yr_parser_emit(yyscanner, instruction, NULL);

      if (instruction != SFOUND)
      {
        string = compiler->current_rule_strings;

        while(!STRING_IS_NULL(string))
        {
          string->g_flags &= ~STRING_GFLAGS_SINGLE_MATCH;
          string = yr_arena_next_address(
              compiler->strings_arena,
              string,
              sizeof(YR_STRING));
        }
      }
    }
    else
    {
      compiler->last_result = ERROR_MISPLACED_ANONYMOUS_STRING;
    }
  }
  else
  {
    string = yr_parser_lookup_string(yyscanner, identifier);

    if (string != NULL)
    {
      yr_parser_emit_with_arg_reloc(
          yyscanner,
          PUSH,
          PTR_TO_UINT64(string),
          NULL);

      if (instruction != SFOUND)
        string->g_flags &= ~STRING_GFLAGS_SINGLE_MATCH;

      yr_parser_emit(yyscanner, instruction, NULL);

      string->g_flags |= STRING_GFLAGS_REFERENCED;
    }
  }

  return compiler->last_result;
}


int yr_parser_reduce_external(
  yyscan_t yyscanner,
  const char* identifier,
  int8_t instruction)
{
  YR_COMPILER* compiler = yyget_extra(yyscanner);
  YR_EXTERNAL_VARIABLE* external;

  external = yr_parser_lookup_external_variable(yyscanner, identifier);

  if (external != NULL)
  {
    if (instruction == EXT_BOOL)
    {
      compiler->last_result = yr_parser_emit_with_arg_reloc(
          yyscanner,
          EXT_BOOL,
          PTR_TO_UINT64(external),
          NULL);
    }
    else if (instruction == EXT_INT &&
             external->type == EXTERNAL_VARIABLE_TYPE_INTEGER)
    {
      compiler->last_result = yr_parser_emit_with_arg_reloc(
          yyscanner,
          EXT_INT,
          PTR_TO_UINT64(external),
          NULL);
    }
    else if (instruction == EXT_STR &&
             external->type == EXTERNAL_VARIABLE_TYPE_FIXED_STRING)
    {
      compiler->last_result = yr_parser_emit_with_arg_reloc(
          yyscanner,
          EXT_STR,
          PTR_TO_UINT64(external),
          NULL);
    }
    else
    {
      yr_compiler_set_error_extra_info(compiler, external->identifier);
      compiler->last_result = ERROR_INCORRECT_VARIABLE_TYPE;
    }
  }

  return compiler->last_result;
}


YR_META* yr_parser_reduce_meta_declaration(
    yyscan_t yyscanner,
    int32_t type,
    const char* identifier,
    const char* string,
    int32_t integer)
{
  YR_COMPILER* compiler = yyget_extra(yyscanner);
  YR_META* meta;

  compiler->last_result = yr_arena_allocate_struct(
      compiler->metas_arena,
      sizeof(YR_META),
      (void**) &meta,
      offsetof(YR_META, identifier),
      offsetof(YR_META, string),
      EOL);

  if (compiler->last_result != ERROR_SUCCESS)
    return NULL;

  compiler->last_result = yr_arena_write_string(
      compiler->sz_arena,
      identifier,
      &meta->identifier);

  if (compiler->last_result != ERROR_SUCCESS)
    return NULL;

  if (string != NULL)
    compiler->last_result = yr_arena_write_string(
        compiler->sz_arena,
        string,
        &meta->string);
  else
    meta->string = NULL;

  if (compiler->last_result != ERROR_SUCCESS)
    return NULL;

  meta->integer = integer;
  meta->type = type;

  return meta;
}


int yr_parser_lookup_loop_variable(
    yyscan_t yyscanner,
    const char* identifier)
{
  YR_COMPILER* compiler = yyget_extra(yyscanner);
  int i;

  for (i = 0; i < compiler->loop_depth; i++)
  {
    if (strcmp(identifier, compiler->loop_identifier[i]) == 0)
      return i;
  }

  return -1;
}


