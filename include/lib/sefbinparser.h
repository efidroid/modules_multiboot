/*
 * Copyright 2016, The EFIDroid Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#ifndef _LIB_SEFBINPARSER_H_
#define _LIB_SEFBINPARSER_H_

#include <lib/list.h>
#include <pcre.h>

typedef struct {
    list_node_t node;

    char *name;
} sefbin_stem_t;

typedef struct {
    list_node_t node;

    char *context;
    char *regex;
    uint32_t mode;
    int32_t stem_id;
    uint32_t hasMetaChars;
    uint32_t prefix_len;
    pcre *pcre_data;
    pcre_extra *pcre_extra;
    uint32_t pcre_data_size;
    void *pcre_studydata;
    uint32_t pcre_studydata_size;
} sefbin_spec_t;

typedef struct  {
    uint32_t version;
    void *pcre_version;
    uint32_t pcre_version_size;
    list_node_t stems;
    list_node_t specs;
} sefbin_file_t;

sefbin_file_t *sefbin_parse(const char *filename);
int sefbin_write(sefbin_file_t *seffile, const char *filename);
int sefbin_append(sefbin_file_t *dst, sefbin_file_t *src);
int sefbin_append_multiboot_rules(sefbin_file_t *dst);
void sefbin_decomp(sefbin_file_t *seffile);
#endif
