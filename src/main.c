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

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <util.h>
#include <common.h>

#define LOG_TAG "MAIN"
#include <lib/log.h>

#include <lib/dynfilefs.h>

static int trigger_main(void)
{
    int rc;
    int fd;

    // init logging
    log_init();

    // restore state
    rc = state_restore();
    if (rc) {
        LOGE("can't restore state\n");
        goto done;
    }

    // get command
    char *cmd = util_get_file_contents(MBPATH_TRIGGER_CMD);
    unlink(MBPATH_TRIGGER_CMD);
    if (!cmd) {
        LOGE("can't read trigger command\n");
        goto done;
    }

    // run trigger handler
    rc = handle_trigger(cmd);

    // cleanup
    free(cmd);

done:
    // tell init to continue (it waits for this file)
    fd = open(MBPATH_TRIGGER_WAIT_FILE, O_RDWR|O_CREAT);
    if (fd) close(fd);

    return rc;
}

int main(int argc, char **argv)
{
    // get program name
    char *progname = util_basename(argv[0]);
    if (!progname) {
        fprintf(stderr, "can't get basename of main executable\n");
        return 1;
    }

    if (!strcmp(progname, "multiboot_init")) {
        if (argc>=2) {
            if (!strcmp(argv[1], "trigger")) {
                return trigger_main();
            } else if (!strcmp(argv[1], "mke2fs")) {
                return mke2fs_main(argc-1, argv+1);
            } else if (!strcmp(argv[1], "busybox")) {
                return busybox_main(argc-1, argv+1);
            } else if (!strcmp(argv[1], "dynfilefs")) {
                log_init();
                return dynfilefs_main(argc-1, argv+1);
            }
        } else {
            multiboot_main(argc, argv);
            MBABORT("multiboot_main returned\n");
        }
    } else if (!strcmp(progname, "trigger")) {
        return trigger_main();
    } else if (!strcmp(progname, "mke2fs")) {
        return mke2fs_main(argc, argv);
    } else if (!strcmp(progname, "busybox")) {
        return busybox_main(argc, argv);
    } else if (!strcmp(progname, "dynfilefs")) {
        return dynfilefs_main(argc, argv);
    }

    fprintf(stderr, "invalid arguments\n");

    return 1;
}
