/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef _MNTENT_H_
#define _MNTENT_H_

#include <stdio.h>
#include <sys/cdefs.h>
#include <paths.h>  /* for _PATH_MOUNTED */
#include <stdint.h>

#define MOUNTED _PATH_MOUNTED
#define MNTTYPE_IGNORE "ignore"

typedef struct {
    uint32_t mnt_id;
    uint32_t mnt_pid;
    uint32_t mnt_major;
    uint32_t mnt_minor;
    char *mnt_root;
    char *mnt_dir;
    char *mnt_opts;
    char *mnt_type;
    char *mnt_fsname;
    char *mnt_superopts;
} mntentex_t;

__BEGIN_DECLS

int endmntentex(FILE *);
mntentex_t *getmntentex(FILE *, mntentex_t *, char *, int);
FILE *setmntentex(const char *, const char *);

__END_DECLS

#endif
