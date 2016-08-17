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

static volatile sig_atomic_t usr_interrupt = 0;
static void synch_signal(UNUSED int sig, UNUSED siginfo_t* info, UNUSED void* vp) {
    // stop waiting for signals
    usr_interrupt = 1;
}

int trigger_postfsdata_main(int argc, char** argv) {
    if(argc!=2)
        return -EINVAL;

    int mbinit_pid = atoi(argv[1]);
    if(mbinit_pid<=0)
        return -EINVAL;

    // setup signal handler for the mbinit callback
    util_setsighandler(SIGUSR1, synch_signal);

    // signal mbinit
    kill(mbinit_pid, SIGUSR1);

    // wait for mbinit to tell us it's finished
    WAIT_FOR_SIGNAL(SIGUSR1, !usr_interrupt);

    // tell init to continue (it waits for this file)
    int fd = open(POSTFS_NOTIFICATION_FILE, O_RDWR|O_CREAT);
    if(fd) close(fd);

    return 0;
}

int main(int argc, char** argv) {
    if(!strcmp(argv[0], MBPATH_TRIGGER_POSTFS_DATA)) {
        return trigger_postfsdata_main(argc, argv);
    }
    else if(!strcmp(argv[0], MBPATH_MKE2FS)) {
        return mke2fs_main(argc, argv);
    }
    else if(!strcmp(argv[0], MBPATH_BUSYBOX)) {
        return busybox_main(argc, argv);
    }
    else {
        int rc = multiboot_main(argc, argv);
        if(rc) {
            MBABORT("multiboot_main returned: %s\n", strerror(-rc));
        }
    }

    return 0;
}
