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

#include "ptrace_helpers.h"
#include <sys/types.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/user.h>

// ptrace helper functions
struct user_regs_struct get_regs(pid_t child_pid, struct user_regs_struct registers) {                                                                                

    int ptrace_result = ptrace(PTRACE_GETREGS, child_pid, 0, &registers);                                                                              
    if (ptrace_result == -1) {                                                                              
        fprintf(stderr, "dragonfly> Error (%d) during ", errno);                                                                              
        perror("ptrace");                                                                              
        exit(errno);                                                                              
    }

    return registers;                                                                              
}

struct user_fpregs_struct get_fp_regs(pid_t child_pid, struct user_fpregs_struct fp_registers) {                                                                           


    int ptrace_result = ptrace(PTRACE_GETFPREGS, child_pid, 0, &fp_registers);        
    if (ptrace_result == -1) {                                                   
        fprintf(stderr, "fp dragonfly> Error (%d) during ", errno);                 
        perror("ptrace");                                                        
        exit(errno);                                                             
    }

    return fp_registers;                                                            
}


void set_regs(pid_t child_pid, struct user_regs_struct registers) {

    int ptrace_result = ptrace(PTRACE_SETREGS, child_pid, 0, &registers);
    if (ptrace_result == -1) {
        fprintf(stderr, "dragonfly> Error (%d) during ", errno);
        perror("ptrace");
        exit(errno);
    }
}

void set_fp_regs(pid_t child_pid, struct user_fpregs_struct fp_registers) {

    int ptrace_result = ptrace(PTRACE_SETFPREGS, child_pid, 0, &fp_registers);
    if (ptrace_result == -1) {
        fprintf(stderr, "fp set dragonfly> Error (%d) during ", errno);
        perror("ptrace");
        exit(errno);
    }
}



long long unsigned get_value(pid_t child_pid, long long unsigned address) {

    errno = 0;
    long long unsigned value = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)address, 0);
    if (value == -1 && errno != 0) {
        fprintf(stderr, "dragonfly> Error (%d) during ", errno);
        perror("ptrace");
        exit(errno);
    }

    return value;	
}

void set_breakpoint(long long unsigned bp_address, long long unsigned original_value, pid_t child_pid) {

    errno = 0;
    long long unsigned breakpoint = (original_value & 0xFFFFFFFFFFFFFF00 | 0xCC);
    int ptrace_result = ptrace(PTRACE_POKETEXT, child_pid, (void*)bp_address, (void*)breakpoint);
    if (ptrace_result == -1 && errno != 0) {
        fprintf(stderr, "dragonfly> Error (%d) during ", errno);
        perror("ptrace");
        exit(errno);
    }
}

void revert_breakpoint(long long unsigned bp_address, long long unsigned original_value, pid_t child_pid) {

    errno = 0;
    int ptrace_result = ptrace(PTRACE_POKETEXT, child_pid, (void*)bp_address, (void*)original_value);
    if (ptrace_result == -1 && errno != 0) {
        fprintf(stderr, "dragonfly> Error (%d) during ", errno);
        perror("ptrace");
        exit(errno);
    }
}

void resume_execution(pid_t child_pid) {

    int ptrace_result = ptrace(PTRACE_CONT, child_pid, 0, 0);
    if (ptrace_result == -1) {
        fprintf(stderr, "dragonfly> Error (%d) during ", errno);
        perror("ptrace");
        exit(errno);
    }
}
