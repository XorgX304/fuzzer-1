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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> 
#include <sys/types.h> 
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/personality.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <sys/uio.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "snapshot.h"
#include "ptrace_helpers.h"
#include "pmparser.h"

// globals /////////////////////////////////////// 
char* debugee = "v7";                           //
size_t prototype_count = 2096;                  //
unsigned char input_prototype[2096];            //
unsigned char input_mutated[2096];              //
void* fuzz_location = (void*)0x7fffffffdab0;    //
int corpus_count = 0;                           //
struct memory
{
    char data[100][2096];
};
struct memory *dataptr;

//////////////////////////////////////////////////

// breakpoints ///////////////////////////////////
long long unsigned start_addr = 0x40188a;       //
long long unsigned end_addr = 0x401892;         // 
//
//////////////////////////////////////////////////

// dynamic breakpoints ///////////////////////////
struct dynamic_breakpoints {                    //
    //
    int bp_count;                               //
    long long unsigned bp_addresses[240];       //
    long long unsigned bp_original_values[240]; //
    //
};                                              //
struct dynamic_breakpoints vuln;                //
//////////////////////////////////////////////////

void set_dynamic_breakpoints(pid_t child_pid) {

    // these are the breakpoints that inform our code coverage
    vuln.bp_count = 240;
    vuln.bp_addresses[0]=0x00000000004015c3;
    vuln.bp_addresses[1]=0x00000000004017d2;
    vuln.bp_addresses[2]=0x0000000000415c30;
    vuln.bp_addresses[3]=0x0000000000420270;
    vuln.bp_addresses[4]=0x00000000004200b0;
    vuln.bp_addresses[5]=0x000000000041ff00;
    vuln.bp_addresses[6]=0x000000000041fee0;
    vuln.bp_addresses[7]=0x00000000004200d0;
    vuln.bp_addresses[8]=0x000000000041fef0;
    vuln.bp_addresses[9]=0x000000000041ff70;
    vuln.bp_addresses[10]=0x000000000040a560;
    vuln.bp_addresses[11]=0x000000000040a5a0;
    vuln.bp_addresses[12]=0x000000000041df80;
    vuln.bp_addresses[13]=0x00000000004215e0;
    vuln.bp_addresses[14]=0x00000000004215a0;
    vuln.bp_addresses[15]=0x0000000000416a40;
    vuln.bp_addresses[16]=0x000000000041f5f0;
    vuln.bp_addresses[17]=0x00000000004176e0;
    vuln.bp_addresses[18]=0x0000000000421190;
    vuln.bp_addresses[19]=0x0000000000421180;
    vuln.bp_addresses[20]=0x00000000004211a0;
    vuln.bp_addresses[21]=0x0000000000420d60;
    vuln.bp_addresses[22]=0x0000000000420c50;
    vuln.bp_addresses[23]=0x0000000000420d00;
    vuln.bp_addresses[24]=0x0000000000421100;
    vuln.bp_addresses[25]=0x0000000000424390;
    vuln.bp_addresses[26]=0x00000000004206b0;
    vuln.bp_addresses[27]=0x00000000004264b0;
    vuln.bp_addresses[28]=0x0000000000420e50;
    vuln.bp_addresses[29]=0x0000000000420910;
    vuln.bp_addresses[30]=0x0000000000420c40;
    vuln.bp_addresses[31]=0x0000000000420a50;
    vuln.bp_addresses[32]=0x0000000000420990;
    vuln.bp_addresses[33]=0x00000000004209d0;
    vuln.bp_addresses[34]=0x0000000000420690;
    vuln.bp_addresses[35]=0x00000000004210e0;
    vuln.bp_addresses[36]=0x00000000004213d0;
    vuln.bp_addresses[37]=0x00000000004211f0;
    vuln.bp_addresses[38]=0x00000000004211b0;
    vuln.bp_addresses[39]=0x00000000004212e0;
    vuln.bp_addresses[40]=0x0000000000421460;
    vuln.bp_addresses[41]=0x0000000000421330;
    vuln.bp_addresses[42]=0x0000000000421400;
    vuln.bp_addresses[43]=0x0000000000421270;
    vuln.bp_addresses[44]=0x0000000000421210;
    vuln.bp_addresses[45]=0x0000000000421500;
    vuln.bp_addresses[46]=0x00000000004210d0;
    vuln.bp_addresses[47]=0x0000000000420c30;
    vuln.bp_addresses[48]=0x0000000000420920;
    vuln.bp_addresses[49]=0x0000000000421160;
    vuln.bp_addresses[50]=0x0000000000421140;
    vuln.bp_addresses[51]=0x0000000000421170;
    vuln.bp_addresses[52]=0x0000000000421120;
    vuln.bp_addresses[53]=0x0000000000421130;
    vuln.bp_addresses[54]=0x00000000004268f0;
    vuln.bp_addresses[55]=0x0000000000420ac0;
    vuln.bp_addresses[56]=0x0000000000420a70;
    vuln.bp_addresses[57]=0x0000000000420bd0;
    vuln.bp_addresses[58]=0x0000000000420930;
    vuln.bp_addresses[59]=0x0000000000420b10;
    vuln.bp_addresses[60]=0x0000000000420b60;
    vuln.bp_addresses[61]=0x0000000000422c10;
    vuln.bp_addresses[62]=0x0000000000424810;
    vuln.bp_addresses[63]=0x0000000000424b90;
    vuln.bp_addresses[64]=0x0000000000424c30;
    vuln.bp_addresses[65]=0x0000000000424cb0;
    vuln.bp_addresses[66]=0x0000000000422de0;
    vuln.bp_addresses[67]=0x0000000000423840;
    vuln.bp_addresses[68]=0x0000000000422af0;
    vuln.bp_addresses[69]=0x00000000004248b0;
    vuln.bp_addresses[70]=0x0000000000424af0;
    vuln.bp_addresses[71]=0x0000000000424860;
    vuln.bp_addresses[72]=0x00000000004238b0;
    vuln.bp_addresses[73]=0x0000000000421470;
    vuln.bp_addresses[74]=0x0000000000415c60;
    vuln.bp_addresses[75]=0x0000000000421610;
    vuln.bp_addresses[76]=0x0000000000421660;
    vuln.bp_addresses[77]=0x00000000004158c0;
    vuln.bp_addresses[78]=0x0000000000409b50;
    vuln.bp_addresses[79]=0x0000000000415ab0;
    vuln.bp_addresses[80]=0x0000000000415920;
    vuln.bp_addresses[81]=0x000000000041def0;
    vuln.bp_addresses[82]=0x000000000041ded0;
    vuln.bp_addresses[83]=0x000000000040a700;
    vuln.bp_addresses[84]=0x000000000041fb40;
    vuln.bp_addresses[85]=0x000000000041fac0;
    vuln.bp_addresses[86]=0x000000000041e0a0;
    vuln.bp_addresses[87]=0x000000000041e190;
    vuln.bp_addresses[88]=0x000000000041e1b0;
    vuln.bp_addresses[89]=0x000000000041e040;
    vuln.bp_addresses[90]=0x000000000041e130;
    vuln.bp_addresses[91]=0x000000000041dfe0;
    vuln.bp_addresses[92]=0x000000000040a3c0;
    vuln.bp_addresses[93]=0x000000000041fa40;
    vuln.bp_addresses[94]=0x000000000040a400;
    vuln.bp_addresses[95]=0x000000000040a440;
    vuln.bp_addresses[96]=0x000000000041fa30;
    vuln.bp_addresses[97]=0x000000000040a5d0;
    vuln.bp_addresses[98]=0x000000000040a280;
    vuln.bp_addresses[99]=0x000000000040a380;
    vuln.bp_addresses[100]=0x000000000040a300;
    vuln.bp_addresses[101]=0x000000000040a2c0;
    vuln.bp_addresses[102]=0x000000000040a340;
    vuln.bp_addresses[103]=0x000000000041fde0;
    vuln.bp_addresses[104]=0x000000000041d020;
    vuln.bp_addresses[105]=0x000000000041f590;
    vuln.bp_addresses[106]=0x000000000041fa60;
    vuln.bp_addresses[107]=0x000000000041fa90;
    vuln.bp_addresses[108]=0x000000000041fdb0;
    vuln.bp_addresses[109]=0x0000000000415800;
    vuln.bp_addresses[110]=0x000000000041f570;
    vuln.bp_addresses[111]=0x000000000041dde0;
    vuln.bp_addresses[112]=0x000000000041fa50;
    vuln.bp_addresses[113]=0x000000000041f580;
    vuln.bp_addresses[114]=0x0000000000408d30;
    vuln.bp_addresses[115]=0x000000000041fb00;
    vuln.bp_addresses[116]=0x000000000041f9f0;
    vuln.bp_addresses[117]=0x000000000041fdc0;
    vuln.bp_addresses[118]=0x0000000000415850;
    vuln.bp_addresses[119]=0x000000000041fa10;
    vuln.bp_addresses[120]=0x000000000041fdd0;
    vuln.bp_addresses[121]=0x000000000041de00;
    vuln.bp_addresses[122]=0x000000000041de20;
    vuln.bp_addresses[123]=0x000000000041fda0;
    vuln.bp_addresses[124]=0x000000000041fd90;
    vuln.bp_addresses[125]=0x000000000041fd70;
    vuln.bp_addresses[126]=0x000000000041fd80;
    vuln.bp_addresses[127]=0x000000000041de40;
    vuln.bp_addresses[128]=0x000000000041f550;
    vuln.bp_addresses[129]=0x000000000041f5a0;
    vuln.bp_addresses[130]=0x000000000041fec0;
    vuln.bp_addresses[131]=0x000000000040a480;
    vuln.bp_addresses[132]=0x000000000041f9d0;
    vuln.bp_addresses[133]=0x0000000000415c10;
    vuln.bp_addresses[134]=0x0000000000420700;
    vuln.bp_addresses[135]=0x000000000041df20;
    vuln.bp_addresses[136]=0x0000000000415d90;
    vuln.bp_addresses[137]=0x0000000000415d20;
    vuln.bp_addresses[138]=0x0000000000421630;
    vuln.bp_addresses[139]=0x0000000000415cb0;
    vuln.bp_addresses[140]=0x000000000041f280;
    vuln.bp_addresses[141]=0x000000000041f0f0;
    vuln.bp_addresses[142]=0x0000000000409b10;
    vuln.bp_addresses[143]=0x0000000000409cb0;
    vuln.bp_addresses[144]=0x0000000000409c10;
    vuln.bp_addresses[145]=0x0000000000417610;
    vuln.bp_addresses[146]=0x000000000040e600;
    vuln.bp_addresses[147]=0x000000000041de60;
    vuln.bp_addresses[148]=0x00000000004175b0;
    vuln.bp_addresses[149]=0x000000000040ad80;
    vuln.bp_addresses[150]=0x000000000040a640;
    vuln.bp_addresses[151]=0x000000000040a6a0;
    vuln.bp_addresses[152]=0x000000000040a6d0;
    vuln.bp_addresses[153]=0x000000000040a670;
    vuln.bp_addresses[154]=0x000000000040af70;
    vuln.bp_addresses[155]=0x000000000040af30;
    vuln.bp_addresses[156]=0x000000000040a6e0;
    vuln.bp_addresses[157]=0x000000000040a800;
    vuln.bp_addresses[158]=0x000000000040aeb0;
    vuln.bp_addresses[159]=0x000000000040af00;
    vuln.bp_addresses[160]=0x0000000000409d60;
    vuln.bp_addresses[161]=0x00000000004018c0;
    vuln.bp_addresses[162]=0x000000000041f5c0;
    vuln.bp_addresses[163]=0x000000000041f5b0;
    vuln.bp_addresses[164]=0x0000000000409bf0;
    vuln.bp_addresses[165]=0x000000000040e6b0;
    vuln.bp_addresses[166]=0x0000000000415820;
    vuln.bp_addresses[167]=0x000000000040af80;
    vuln.bp_addresses[168]=0x000000000040a7c0;
    vuln.bp_addresses[169]=0x0000000000415ae0;
    vuln.bp_addresses[170]=0x000000000041d030;
    vuln.bp_addresses[171]=0x000000000041dcc0;
    vuln.bp_addresses[172]=0x000000000041dc50;
    vuln.bp_addresses[173]=0x000000000041dbe0;
    vuln.bp_addresses[174]=0x000000000041dc10;
    vuln.bp_addresses[175]=0x000000000041d0a0;
    vuln.bp_addresses[176]=0x000000000041db80;
    vuln.bp_addresses[177]=0x000000000041f600;
    vuln.bp_addresses[178]=0x000000000041f8f0;
    vuln.bp_addresses[179]=0x000000000041f970;
    vuln.bp_addresses[180]=0x000000000041f9a0;
    vuln.bp_addresses[181]=0x000000000041f6b0;
    vuln.bp_addresses[182]=0x000000000041f960;
    vuln.bp_addresses[183]=0x000000000041f7f0;
    vuln.bp_addresses[184]=0x000000000041ef90;
    vuln.bp_addresses[185]=0x000000000041e330;
    vuln.bp_addresses[186]=0x0000000000409bc0;
    vuln.bp_addresses[187]=0x000000000041f430;
    vuln.bp_addresses[188]=0x000000000040ea10;
    vuln.bp_addresses[189]=0x000000000041f330;
    vuln.bp_addresses[190]=0x000000000041f400;
    vuln.bp_addresses[191]=0x000000000041e1d0;
    vuln.bp_addresses[192]=0x000000000041e290;
    vuln.bp_addresses[193]=0x000000000041e2e0;
    vuln.bp_addresses[194]=0x000000000041e220;
    vuln.bp_addresses[195]=0x0000000000409da0;
    vuln.bp_addresses[196]=0x000000000041d010;
    vuln.bp_addresses[197]=0x0000000000408d10;
    vuln.bp_addresses[198]=0x0000000000415810;
    vuln.bp_addresses[199]=0x000000000041ddf0;
    vuln.bp_addresses[200]=0x000000000041cfc0;
    vuln.bp_addresses[201]=0x0000000000408d40;
    vuln.bp_addresses[202]=0x000000000041fa00;
    vuln.bp_addresses[203]=0x000000000041cff0;
    vuln.bp_addresses[204]=0x000000000041fa20;
    vuln.bp_addresses[205]=0x000000000041d000;
    vuln.bp_addresses[206]=0x000000000041de10;
    vuln.bp_addresses[207]=0x000000000041cfd0;
    vuln.bp_addresses[208]=0x000000000041de30;
    vuln.bp_addresses[209]=0x000000000041cfe0;
    vuln.bp_addresses[210]=0x000000000041de50;
    vuln.bp_addresses[211]=0x000000000041f560;
    vuln.bp_addresses[212]=0x00000000004205d0;
    vuln.bp_addresses[213]=0x0000000000408ce0;
    vuln.bp_addresses[214]=0x0000000000408cd0;
    vuln.bp_addresses[215]=0x0000000000421a20;
    vuln.bp_addresses[216]=0x0000000000422230;
    vuln.bp_addresses[217]=0x00000000004226d0;
    vuln.bp_addresses[218]=0x00000000004222c0;
    vuln.bp_addresses[219]=0x00000000004223c0;
    vuln.bp_addresses[220]=0x00000000004224f0;
    vuln.bp_addresses[221]=0x00000000004225a0;
    vuln.bp_addresses[222]=0x0000000000421fc0;
    vuln.bp_addresses[223]=0x0000000000409ab0;
    vuln.bp_addresses[224]=0x0000000000421f80;
    vuln.bp_addresses[225]=0x0000000000421f90;
    vuln.bp_addresses[226]=0x0000000000408db0;
    vuln.bp_addresses[227]=0x0000000000421fa0;
    vuln.bp_addresses[228]=0x0000000000421fb0;
    vuln.bp_addresses[229]=0x0000000000421f70;
    vuln.bp_addresses[230]=0x0000000000421ee0;
    vuln.bp_addresses[231]=0x00000000004220f0;
    vuln.bp_addresses[232]=0x0000000000408e10;
    vuln.bp_addresses[233]=0x0000000000422030;
    vuln.bp_addresses[234]=0x0000000000409ac0;
    vuln.bp_addresses[235]=0x0000000000408dc0;
    vuln.bp_addresses[236]=0x0000000000408d90;
    vuln.bp_addresses[237]=0x0000000000408d60;
    vuln.bp_addresses[238]=0x00000000004236c0;
    vuln.bp_addresses[239]=0x0000000000408cf0;
    vuln.bp_addresses[240]=0x0000000000400c20;

    for (int i = 0; i < vuln.bp_count; i++) {
        vuln.bp_original_values[i] = get_value(child_pid, vuln.bp_addresses[i]);
    }
    //printf("\033[1;35mdragonfly>\033[0m original dynamic breakpoint values collected\n");

    for (int i = 0; i < vuln.bp_count; i++) {
        set_breakpoint(vuln.bp_addresses[i], vuln.bp_original_values[i], child_pid);
    }
    printf("\033[1;35mdragonfly>\033[0m set dynamic breakpoints: \n\n");
    for (int i = 0; i < vuln.bp_count; i++) {
        printf("           0x%llx\n", vuln.bp_addresses[i]);
    }
    printf("\n");
}

void restore_dynamic_breakpoint(pid_t child_pid, long long unsigned bp_addr) {

    int reverted = 0; 
    for (int i = 0; i < vuln.bp_count; i++) {
        if (vuln.bp_addresses[i] == bp_addr) {
            revert_breakpoint(bp_addr, vuln.bp_original_values[i], child_pid);
            reverted++;
        }
    }
    if (!reverted) {
        printf("\033[1;35mdragonfly>\033[0m unable to revert breakpoint: 0x%llx\n", bp_addr);
        exit(-1);
    }
}

void add_to_corpus(unsigned char *new_input) {

    corpus_count++;
    strcpy(dataptr->data[corpus_count-1],new_input);

}

void add_code_coverage(pid_t child_pid, struct user_regs_struct registers) {

    // search through dynamic breakpoints for match so we can restore original value
    restore_dynamic_breakpoint(child_pid, registers.rip - 1);

    // save input in heap
    unsigned char *new_input = (unsigned char*)malloc(prototype_count);
    memcpy(new_input, input_mutated, prototype_count);
    add_to_corpus(new_input);

}

unsigned char* get_fuzzcase() {

    // default corpus, ie, the prototype input only (fast)
    if (corpus_count == 0) {
        memcpy(input_mutated, input_prototype, prototype_count);

        // mutate
        for (int i = 0; i < rand() % 4; i++) {
            input_mutated[rand() % prototype_count] = (unsigned char)(rand() % 256);
        }


        return input_mutated;
    }

    // if we're here, that means our corpus has been added to
    // by code coverage feedback and we're doing lookups in shared memory
    else {

        // leave a possibility of still using prototype input 10% of the time
        int choice = rand() % 10;

        // if we select 0 here, use prototype instead of new inputs we got
        if (choice == 0) {
            memcpy(input_mutated, input_prototype, prototype_count);

            // mutate
            for (int i = 0; i < rand() % 4; i++) {
                input_mutated[rand() % prototype_count] = (unsigned char)(rand() % 256);
            }



            return input_mutated;
        }
        // here we'll pick a random input from the corpus 
        else {
            int corpus_pick = rand() % corpus_count;
            memcpy(input_mutated, dataptr->data[corpus_pick], prototype_count);

            for (int i = 0; i < rand() % 4; i++) {
                input_mutated[rand() % prototype_count] = (unsigned char)(rand() % 256);
            }



            return input_mutated;
        }
    }
}

void insert_fuzzcase(unsigned char* input_mutated, pid_t child_pid) {


    struct iovec local[1];
    struct iovec remote[1];

    local[0].iov_base = input_mutated;
    local[0].iov_len = prototype_count;

    remote[0].iov_base = fuzz_location;
    remote[0].iov_len = prototype_count;

    ssize_t bytes_written = process_vm_writev(child_pid, local, 1, remote, 1, 0);
}

void log_crash(int child_pid, unsigned char* crash_input, struct user_regs_struct crash_registers) {

    // name file with crash rip and signal
    char file_name[0x30];
    sprintf(file_name, "crashes/11_%i_%llx", child_pid, crash_registers.rip);

    // write to disk
    FILE *fileptr;
    fileptr = fopen(file_name, "wb");
    if (fileptr == NULL) {
        printf("\033[1;35mdragonfly>\033[0m unable to log crash data.\n");
        return;
    }
    char regs[512];

    sprintf(regs, "$rip:%llx\n$rax:%llx\n$rbx:%llx\n$rdx:%llx\n$rcx:%llx\n$rdi:%llx\n", crash_registers.rip, crash_registers.rax, crash_registers.rbx, crash_registers.rdx,crash_registers.rcx,crash_registers.rdi);
    fwrite(regs, 1, strlen(regs), fileptr);
    fwrite(crash_input, 1, prototype_count, fileptr);
    fclose(fileptr);
}

void print_stats(int result, int crashes, float million_iterations) {

    float percentage = (float) corpus_count / vuln.bp_count * 100;

    printf("\e[?25l\n\033[1;36mfc/s\033[0m       : %d\n\033[1;36mcrashes\033[0m"
            "    : %d\n\033[1;36miterations\033[0m : %0.1fm"
            "\n\033[1;36mcoverage\033[0m   : %d/%d (%.2f%%)"
            "\033[F\033[F\033[F\033[F",
            result, crashes, million_iterations, corpus_count, vuln.bp_count, percentage);
    fflush(stdout);
}

void fuzzer(pid_t child_pid, unsigned char* snapshot_buf,  long  maps_offset[], long snapshot_buf_offset[], long rdwr_len[], int count, struct user_regs_struct snapshot_registers, struct user_fpregs_struct snapshot_fp_registers) {

    // fc/s
    int iterations = 0;
    int crashes = 0;
    clock_t t;
    t = clock();

    int wait_status;

    struct user_regs_struct temp_registers;
    printf("\r\033[1;35mdragonfly>\033[0m stats (target:\033[1;32m%s\033[0m, pid:\033[1;32m%d\033[0m)\n",
            debugee, child_pid);
    int i=0;
    while (1) {


        // insert our fuzzcase into the heap
        unsigned char* input_mutated = get_fuzzcase();
        insert_fuzzcase(input_mutated, child_pid);
        // restore registers to their state at Start
        set_regs(child_pid, snapshot_registers);
        set_fp_regs(child_pid, snapshot_fp_registers);


        resume_execution(child_pid);


        // wait for debuggee to finish/reach breakpoint
        wait(&wait_status);
        if (WIFSTOPPED(wait_status)) {
            // 5 means we hit a bp
            if (WSTOPSIG(wait_status) == 5) {

                temp_registers = get_regs(child_pid, temp_registers);
                if (temp_registers.rip - 1 != end_addr) {
                    add_code_coverage(child_pid, temp_registers);
                }
            }
            else {
                crashes++;
                temp_registers = get_regs(child_pid, temp_registers);
                log_crash(i, input_mutated, temp_registers);
            }
        }
        else {
            fprintf(stderr, "\033[1;35mdragonfly>\033[0m error (%d) during ", errno);
            perror("wait");
            return;
        }

        // restore writable memory from /proc/$pid/maps to its state at Start
        restore_snapshot(snapshot_buf, child_pid, maps_offset, snapshot_buf_offset, rdwr_len, count);

        // restore registers to their state at Start
        set_regs(child_pid, snapshot_registers);
        set_fp_regs(child_pid, snapshot_fp_registers);
        iterations++;
        if (iterations % 50000 == 0) {
            clock_t total = clock() - t;
            double time_taken = ((double)total)/CLOCKS_PER_SEC;
            float million_iterations = (float)iterations / 1000000;
            int result = (int) iterations / time_taken;
            print_stats(result, crashes, million_iterations);
        }
        i=i+1;
    }
}

void sig_handler(int s) {
    printf("\e[?25h");
    printf("\n\n\n\n\n\n\033[1;35mdragonfly>\033[0m caught user-interrupt, exiting...\n");
    printf("\n");
    exit(0);
}

void scan_input() {

    //memcpy(input_prototype,"\x1\x1\x1\x1\x1\x1\x1\x1\x1\x1\x1\x1",12);
}

void execute_debugee(char* debugee) {

    // request via PTRACE_TRACEME that the parent trace the child
    long ptrace_result = ptrace(PTRACE_TRACEME, 0, 0, 0);
    if (ptrace_result == -1) {
        fprintf(stderr, "\033[1;35mdragonfly>\033[0m error (%d) during ", errno);
        perror("ptrace");
        exit(errno);
    }

    // disable ASLR
    int personality_result = personality(ADDR_NO_RANDOMIZE);
    if (personality_result == -1) {
        fprintf(stderr, "\033[1;35mdragonfly>\033[0m error (%d) during ", errno);
        perror("personality");
        exit(errno);
    }

    // dup both stdout and stderr and send them to /dev/null
    int fd = open("/dev/null", O_WRONLY);
    dup2(fd, 1);
    dup2(fd, 2);
    close(fd);
    // exec our debugee program, NULL terminated to avoid Sentinel compilation
    // warning. this replaces the fork() clone of the parent with the 
    // debugee process 
    int execl_result = execl(debugee, debugee, NULL);
    if (execl_result == -1) {
        fprintf(stderr, "\033[1;35mdragonfly>\033[0m error (%d) during ", errno);
        perror("execl");
        exit(errno);
    }
}

void execute_debugger(pid_t child_pid) {

    printf("\033[1;35mdragonfly>\033[0m debuggee pid: %d\n", child_pid);

    printf("\033[1;35mdragonfly>\033[0m setting 'start/end' breakpoints:\n\n   "
            "start-> 0x%llx\n   end  -> 0x%llx\n\n", start_addr, end_addr);

    int wait_status;
    unsigned instruction_counter = 0;
    struct user_regs_struct registers;

    // will SIGTRAP before any subsequent calls to exec
    wait(&wait_status);

    // retrieve the original data at start_addr
    long long unsigned start_val = get_value(child_pid, start_addr);

    // set breakpoint on start_addr
    set_breakpoint(start_addr, start_val, child_pid);

    // retrieve the original data at end_addr
    long long unsigned end_val = get_value(child_pid, end_addr);

    // set breakpoint on end_addr
    set_breakpoint(end_addr, end_val, child_pid);
    //printf("\033[1;35mdragonfly>\033[0m breakpoints set\n");

    //printf("\033[1;35mdragonfly>\033[0m resuming debugee execution...\n");
    resume_execution(child_pid);

    // we've now resumed execution and should stop on our first bp
    wait(&wait_status);
    if (WIFSTOPPED(wait_status)) {
        if (WSTOPSIG(wait_status) == 5) {
            registers = get_regs(child_pid, registers);
            //printf("\033[1;35mdragonfly>\033[0m reached breakpoint at: 0x%llx\n", (registers.rip - 1));
        }
        else {
            printf("dragonfly > Debugee signaled, reason: %s\n",
                    strsignal(WSTOPSIG(wait_status)));
        }
    }
    else {
        fprintf(stderr, "\033[1;35mdragonfly>\033[0m error (%d) during ", errno);
        perror("ptrace");
        return;
    }

    // now that we've broken on start, we can revert the breakpoint
    revert_breakpoint(start_addr, start_val, child_pid);

    // rewind rip backwards by one since its at start+1
    // reset registers
    registers.rip -= 1;
    set_regs(child_pid, registers);



    //printf("\033[1;35mdragonfly>\033[0m setting dynamic breakpoints...\n");
    set_dynamic_breakpoints(child_pid);

    // take a snapshot of the writable memory sections in /proc/$pid/maps
    printf("\033[1;35mdragonfly>\033[0m collecting snapshot data\n");
    procmaps_iterator* maps = pmparser_parse(child_pid);
    procmaps_struct* maps_tmp=NULL;
    int i=0; 
    long maps_offset[255];
    long snapshot_buf_offset[255];
    long rdwr_len[255];
    long offset[255];
    while( (maps_tmp = pmparser_next(maps)) != NULL){
        if(maps_tmp->is_r && maps_tmp->is_w)
        {


            offset[i]=maps_tmp->length;
            maps_offset[i]=(long) maps_tmp->addr_start;
            if(i==0)
                snapshot_buf_offset[i]=0x0;
            else if(i==1)
                snapshot_buf_offset[i]=snapshot_buf_offset[i-1]+offset[i-1]-0x1;
            else
                snapshot_buf_offset[i]=snapshot_buf_offset[i-1]+offset[i-1];

            rdwr_len[i]=maps_tmp->length;
            i=i+1;



        } 
    }


    pmparser_free(maps);


    unsigned char* snapshot_buf = create_snapshot(child_pid, maps_offset, snapshot_buf_offset, rdwr_len, i);

    // take a snapshot of the registers in this state
    struct user_regs_struct snapshot_registers = get_regs(child_pid, snapshot_registers);
    struct user_fpregs_struct snapshot_fp_registers = get_fp_regs(child_pid, snapshot_fp_registers);


    // snapshot capturing complete, ready to fuzz
    printf("\033[1;35mdragonfly>\033[0m snapshot collection complete\n"
            "\033[1;35mdragonfly>\033[0m press any key to start fuzzing!\n");
    getchar();

    // system("clear");
    fuzzer(child_pid, snapshot_buf, maps_offset, snapshot_buf_offset, rdwr_len, i, snapshot_registers, snapshot_fp_registers);
}

int main(int argc, char* argv[]) {

    int size = sizeof(struct memory) - 1;  
    printf("size:%i\n",size);
    int shm_id;
    key_t shmKey;

    shmKey = ftok(".",1234);


    shm_id  = shmget(shmKey, size, 0666 | IPC_CREAT);   /* I adjusted the size parameter here */

    if(shm_id < 0)
    {
        perror("shm_id didn't create\n");
        exit(0);
    }

    dataptr = (struct memory *)shmat(shm_id,NULL,0);
    if((long) dataptr == -1)
    {
        perror("****didn't attatch to share memory\n");
        exit(0);
    }

    printf("share memory attatched at %p address\n",dataptr);



    // setting up a signal handler so we can exit gracefully from our
    // continuous fuzzing loop that is a while true

    //long long loc = strtoll(argv[1],NULL,0);
    //fuzz_location = (void*)loc+16; // in my case needed to shift due to vars 
    printf("fuzz_location:%p\n",fuzz_location);

    struct sigaction sig_int_handler;
    sig_int_handler.sa_handler = sig_handler;
    sigemptyset(&sig_int_handler.sa_mask);
    sig_int_handler.sa_flags = 0;
    sigaction(SIGINT, &sig_int_handler, NULL);

    srand((unsigned)time(NULL));

    // scan prototypical input into memory so that it can be used
    // to seed fuzz cases
    scan_input();

    printf("\n");

    pid_t child_pid = fork();
    if (child_pid == 0) {
        //we're the child process here
        execute_debugee(debugee);
    }

    else {
        //we're the parent process here
        execute_debugger(child_pid);
    }

    munmap(dataptr, size );
    return 0;    
}

