/*
   @Author    : h0mbre, marcinguy
   @date      : July 2020

   Permission to use, copy, modify, distribute, and sell this software and its
   documentation for any purpose is hereby granted without fee, provided that
   the above copyright notice appear in all copies and that both that
   copyright notice and this permission notice appear in supporting
   documentation.  No representations are made about the suitability of this
   software for any purpose.  It is provided "as is" without express or
   implied warranty.
 */


#define _GNU_SOURCE
#include "snapshot.h"
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

unsigned char* create_snapshot(pid_t child_pid, long maps_offset[], long snapshot_buf_offset[], long rdwr_len[], int count) {


    struct SNAPSHOT_MEMORY read_memory;

    memcpy(read_memory.maps_offset,maps_offset,(count)*sizeof(long));
    memcpy(read_memory.snapshot_buf_offset,snapshot_buf_offset,(count)*sizeof(long));
    memcpy(read_memory.rdwr_length,rdwr_len,(count)*sizeof(long));





    unsigned char* snapshot_buf = (unsigned char*)malloc(0xffff0);

    // this is just /proc/$pid/mem
    char proc_mem[0x20] = { 0 };
    sprintf(proc_mem, "/proc/%d/mem", child_pid);

    // open /proc/$pid/mem for reading
    // hardcoded offsets are from typical /proc/$pid/maps at main()
    int mem_fd = open(proc_mem, O_RDONLY);
    if (mem_fd == -1) {
        fprintf(stderr, "dragonfly> Error (%d) during ", errno);
        perror("open");
        exit(errno);
    }

    // this loop will:
    //  -- go to an offset within /proc/$pid/mem via lseek()
    //  -- read x-pages of memory from that offset into the snapshot buffer
    //  -- adjust the snapshot buffer offset so nothing is overwritten in it
    int lseek_result, bytes_read;
    for (int i = 0; i < count; i++) {
        printf("dragonfly> Reading from offset: %d\n", i);
        lseek_result = lseek(mem_fd, read_memory.maps_offset[i], SEEK_SET);
        if (lseek_result == -1) {
            fprintf(stderr, "dragonfly> Error (%d) during ", errno);
            perror("lseek");
            exit(errno);
        }

        bytes_read = read(mem_fd,
                (unsigned char*)(snapshot_buf + read_memory.snapshot_buf_offset[i]),
                read_memory.rdwr_length[i]);
        if (bytes_read == -1) {
            fprintf(stderr, "dragonfly> Error (%d) during ", errno);
            perror("read");
            exit(errno);
        }
        //printf("dragonfly> %ld bytes read\n", bytes_read);

    }

    close(mem_fd);
    return snapshot_buf;
}

void restore_snapshot(unsigned char* snapshot_buf, pid_t child_pid, long maps_offset[], long snapshot_buf_offset[],long rdwr_len[], int count) {
    ssize_t bytes_written = 0;

    // we're writing *from* 7 different offsets within snapshot_buf
    struct iovec local[count];
    // we're writing *to* 7 separate sections of writable memory here
    struct iovec remote[count];




    // this struct is the local buffer we want to write from into the 
    // struct that is 'remote' (ie, the child process where we'll overwrite
    // all of the non-heap writable memory sections that we parsed from 
    // proc/$pid/memory)

    for(int i=0;i<count;i++)
    {  


        if(i==0)
        { 
            local[i].iov_base = (unsigned char*)(snapshot_buf);
            local[i].iov_len = rdwr_len[i];
        }else{

            local[i].iov_base = (unsigned char*)(snapshot_buf+snapshot_buf_offset[i]);
            local[i].iov_len = rdwr_len[i];
        }

    }

    for(int i=0;i<count;i++)
    {
        remote[i].iov_base = (void *)(maps_offset[i]);
        remote[i].iov_len = rdwr_len[i];
    }



    bytes_written = process_vm_writev(child_pid, local, count, remote, count, 0);
    //printf("dragonfly> %ld bytes written\n", bytes_written);
}
