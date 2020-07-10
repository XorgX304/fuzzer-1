#include <sys/types.h>

struct SNAPSHOT_MEMORY {
    long long unsigned maps_offset[255];
    long long unsigned snapshot_buf_offset[255];
    long long unsigned rdwr_length[255];
};

unsigned char* create_snapshot(pid_t child_pid, long maps_offset[], long snapshot_buf_offset[], long rdwr_len[], int count);

void restore_snapshot(unsigned char* snapshot_buf, pid_t child_pid,  long maps_offset[], long snapshot_buf_offset[], long rdwr_len[], int count);
