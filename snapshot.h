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

#include <sys/types.h>

struct SNAPSHOT_MEMORY {
    long long unsigned maps_offset[255];
    long long unsigned snapshot_buf_offset[255];
    long long unsigned rdwr_length[255];
};

unsigned char* create_snapshot(pid_t child_pid, long maps_offset[], long snapshot_buf_offset[], long rdwr_len[], int count);

void restore_snapshot(unsigned char* snapshot_buf, pid_t child_pid,  long maps_offset[], long snapshot_buf_offset[], long rdwr_len[], int count);
