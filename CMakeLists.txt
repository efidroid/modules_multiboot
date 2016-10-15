cmake_minimum_required(VERSION 2.8)
project(multiboot)
set(CMAKE_BUILD_TYPE Release)

add_custom_command(
    OUTPUT file_contexts.bin

    # dependencies
    DEPENDS ${CMAKE_SOURCE_DIR}/file_contexts

    COMMAND ${HOST_SELINUXTOOLS_OUT}/libselinux/utils/sefcontext_compile -o file_contexts.bin ${CMAKE_SOURCE_DIR}/file_contexts
)

set(CMAKE_PAYLOADS
    ${DEVICE_FSTAB}
    file_contexts.bin
    ${CMAKE_SOURCE_DIR}/file_contexts
)
set(CMAKE_PAYLOAD_DIR ${CMAKE_CURRENT_BINARY_DIR}/files)
set(CMAKE_PAYLOAD_OBJ ${CMAKE_PAYLOAD_DIR}.obj)
add_custom_command(
    OUTPUT payload.o

    # dependencies
    DEPENDS ${CMAKE_PAYLOADS}

    # copy all files
    COMMAND mkdir -p ${CMAKE_PAYLOAD_DIR}
    COMMAND rm -f ${CMAKE_PAYLOAD_DIR}/*
    COMMAND cp ${CMAKE_PAYLOADS} ${CMAKE_PAYLOAD_DIR}/

    # compile all files into a single object
    COMMAND mkdir -p ${CMAKE_PAYLOAD_OBJ}
    COMMAND rm -f ${CMAKE_PAYLOAD_OBJ}/*.o
    COMMAND cd ${CMAKE_PAYLOAD_DIR} && find * -maxdepth 0 -type f -print | xargs -I {} sh -c \"${CMAKE_LINKER} -r -b binary -o ${CMAKE_PAYLOAD_OBJ}/{}.o {} && ${CMAKE_OBJCOPY} --rename-section .data=.rodata,alloc,load,readonly,data,contents ${CMAKE_PAYLOAD_OBJ}/{}.o ${CMAKE_PAYLOAD_OBJ}/{}.o\"
    COMMAND ${CMAKE_LINKER} -r -o ${CMAKE_CURRENT_BINARY_DIR}/payload.o ${CMAKE_PAYLOAD_OBJ}/*.o

)
add_library(payload
    STATIC
    payload.o
)
set_source_files_properties(payload.o PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)
set_target_properties(payload PROPERTIES
    LINKER_LANGUAGE C
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror -Wshadow")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -static-libgcc -Wl,-static")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffunction-sections -fdata-sections -Wl,-gc-sections -Os -s")
add_definitions(-DDEVICE_NVVARS_PARTITION="${DEVICE_NVVARS_PARTITION}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DSIMPLEFILENAME='\"$(subst ${CMAKE_SOURCE_DIR}/,,$(abspath $<))\"'")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DINI_STOP_ON_FIRST_ERROR=1")

# main
add_executable(init
    # main code
    src/main.c
    src/multiboot_init.c
    src/util.c
    src/safe.c
    src/state.c
    src/boot_recovery.c
    src/boot_android.c
    src/syscalls/init.c
    src/syscalls/syscalls.c
    src/syscalls/utils.c

    # libs
    lib/efivars.c
    lib/log.c
    lib/sefbinparser.c
    lib/sefsrcparser.c
    lib/uevent.c
    lib/dmcrypt.c
    lib/android/bionic/strlcpy.c
    lib/android/bionic/strlcat.c
    lib/android/bionic/mntentex.c
    lib/android/cutils/klog.c
    lib/android/cutils/android_reboot.c
    lib/android/fs_mgr/fs_mgr_fstab.c
    lib/android/fs_mgr/fs_mgr_search.c
    lib/android/fs_mgr/fs_mgr_slotselect.c
    lib/android/init/cmdline.c
    lib/android/recovery/mounts.c
    lib/lk/cksum/crc32.c
)
target_link_libraries(init
    mke2fs e2p support com_err ext2fs
    busybox
    blkid uuid sepolicy_inject sepol6 sepol7 dynfilefs syshook inih payload fuse pthread dl pcre
)
include_directories(
    include
    lib/android/include
    lib/android/fs_mgr/include
    lib/lk/include
)
