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

#include <string.h>
#include <stdio.h>
#include <lib/mntentex.h>

mntentex_t *getmntentex(FILE *fp, mntentex_t *e, char *buf, int buf_len)
{
    memset(e, 0, sizeof(*e));

    while (fgets(buf, buf_len, fp) != NULL) {

        // Entries look like "13 1 0:3 / /proc rw,relatime - proc proc rw"
        // That is: mountid parentid major:minor mnt_root mnt_dir mnt_opts [opt_fields] - mnt_type mnt_fsname super_opts
        int root0, root1, dir0, dir1, opts0, opts1;
        if (sscanf(buf, " %u %u %u:%u %n%*s%n %n%*s%n %n%*s%n",
                   &e->mnt_id, &e->mnt_pid, &e->mnt_major, &e->mnt_minor,
                   &root0, &root1, &dir0, &dir1, &opts0, &opts1) != 4) {
            continue;
        }

        e->mnt_root = &buf[root0];
        buf[root1] = '\0';

        e->mnt_dir = &buf[dir0];
        buf[dir1] = '\0';

        e->mnt_opts = &buf[opts0];
        buf[opts1] = '\0';

        char *rest = &buf[opts1+1];
        char *past_optfields = strstr(rest, "-");
        if (!past_optfields) continue;
        past_optfields++;

        int type0, type1, fsname0, fsname1, superopts0, superopts1;
        if (sscanf(past_optfields, " %n%*s%n %n%*s%n %n%*s%n",
                   &type0, &type1, &fsname0, &fsname1, &superopts0, &superopts1) != 0) {
            continue;
        }

        e->mnt_type = &past_optfields[type0];
        past_optfields[type1] = '\0';

        e->mnt_fsname = &past_optfields[fsname0];
        past_optfields[fsname1] = '\0';

        e->mnt_superopts = &past_optfields[superopts0];
        past_optfields[superopts1] = '\0';

        return e;
    }
    return NULL;
}

FILE *setmntentex(const char *path, const char *mode)
{
    return fopen(path, mode);
}

int endmntentex(FILE *fp)
{
    if (fp != NULL) {
        fclose(fp);
    }
    return 1;
}
