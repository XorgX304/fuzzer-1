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
#include <unistd.h>
#include <sys/user.h>

struct user_regs_struct get_regs(pid_t child_pid, struct user_regs_struct registers);
struct user_fpregs_struct get_fp_regs(pid_t child_pid, struct user_fpregs_struct registers);


void set_regs(pid_t child_pid, struct user_regs_struct registers);
void set_fp_regs(pid_t child_pid, struct user_fpregs_struct registers);


long long unsigned get_value(pid_t child_pid, long long unsigned address);

void set_breakpoint(long long unsigned bp_address, long long unsigned original_value, pid_t child_pid);

void revert_breakpoint(long long unsigned bp_address, long long unsigned original_value, pid_t child_pid);

void resume_execution(pid_t child_pid);
