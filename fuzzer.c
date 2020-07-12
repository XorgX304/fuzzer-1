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
char* debugee = "v6";                           //
size_t prototype_count = 12;                    //
unsigned char input_prototype[12];              //
unsigned char input_mutated[12];                //
void* fuzz_location = (void*)0x7fffffffd9e0;    //
int corpus_count = 0;                           //
struct memory
{
    char data[100][12];
};
struct memory *dataptr;
unsigned char *corpus[100];

//////////////////////////////////////////////////

// breakpoints ///////////////////////////////////
long long unsigned start_addr =0x400b40;        //
long long unsigned end_addr = 0x400baa;         // 
                                                //
//////////////////////////////////////////////////

// dynamic breakpoints ///////////////////////////
struct dynamic_breakpoints {                    //
                                                //
    int bp_count;                               //
    long long unsigned bp_addresses[123];       //
    long long unsigned bp_original_values[123]; //
                                                //
};                                              //
struct dynamic_breakpoints vuln;                //
//////////////////////////////////////////////////

void set_dynamic_breakpoints(pid_t child_pid) {

    // these are the breakpoints that inform our code coverage
    vuln.bp_count = 123;
    vuln.bp_addresses[0]=0x000000000040da90;
    vuln.bp_addresses[1]=0x000000000040d7b0;
    vuln.bp_addresses[2]=0x000000000040fb80;
    vuln.bp_addresses[3]=0x000000000040fb40;
    vuln.bp_addresses[4]=0x000000000040e540;
    vuln.bp_addresses[5]=0x000000000040f720;
    vuln.bp_addresses[6]=0x000000000040f710;
    vuln.bp_addresses[7]=0x000000000040f730;
    vuln.bp_addresses[8]=0x000000000040f3b0;
    vuln.bp_addresses[9]=0x000000000040f2a0;
    vuln.bp_addresses[10]=0x000000000040f350;
    vuln.bp_addresses[11]=0x000000000040f690;
    vuln.bp_addresses[12]=0x000000000040f4a0;
    vuln.bp_addresses[13]=0x000000000040efd0;
    vuln.bp_addresses[14]=0x000000000040f290;
    vuln.bp_addresses[15]=0x000000000040f0a0;
    vuln.bp_addresses[16]=0x000000000040eff0;
    vuln.bp_addresses[17]=0x000000000040f030;
    vuln.bp_addresses[18]=0x000000000040ef80;
    vuln.bp_addresses[19]=0x000000000040f670;
    vuln.bp_addresses[20]=0x000000000040f780;
    vuln.bp_addresses[21]=0x000000000040f740;
    vuln.bp_addresses[22]=0x000000000040f8b0;
    vuln.bp_addresses[23]=0x000000000040f870;
    vuln.bp_addresses[24]=0x000000000040fa00;
    vuln.bp_addresses[25]=0x000000000040f900;
    vuln.bp_addresses[26]=0x000000000040f880;
    vuln.bp_addresses[27]=0x000000000040f9a0;
    vuln.bp_addresses[28]=0x000000000040f800;
    vuln.bp_addresses[29]=0x000000000040f7a0;
    vuln.bp_addresses[30]=0x000000000040faa0;
    vuln.bp_addresses[31]=0x000000000040f660;
    vuln.bp_addresses[32]=0x000000000040f280;
    vuln.bp_addresses[33]=0x000000000040efe0;
    vuln.bp_addresses[34]=0x000000000040f6f0;
    vuln.bp_addresses[35]=0x000000000040f6d0;
    vuln.bp_addresses[36]=0x000000000040f700;
    vuln.bp_addresses[37]=0x000000000040f6b0;
    vuln.bp_addresses[38]=0x000000000040f6c0;
    vuln.bp_addresses[39]=0x000000000040f110;
    vuln.bp_addresses[40]=0x000000000040f0c0;
    vuln.bp_addresses[41]=0x000000000040f220;
    vuln.bp_addresses[42]=0x000000000040f160;
    vuln.bp_addresses[43]=0x000000000040f1b0;
    vuln.bp_addresses[44]=0x0000000000411720;
    vuln.bp_addresses[45]=0x0000000000411440;
    vuln.bp_addresses[46]=0x00000000004118f0;
    vuln.bp_addresses[47]=0x00000000004113d0;
    vuln.bp_addresses[48]=0x00000000004115f0;
    vuln.bp_addresses[49]=0x00000000004114e0;
    vuln.bp_addresses[50]=0x0000000000411490;
    vuln.bp_addresses[51]=0x000000000040fa10;
    vuln.bp_addresses[52]=0x000000000040dac0;
    vuln.bp_addresses[53]=0x00000000004106c0;
    vuln.bp_addresses[54]=0x00000000004106f0;
    vuln.bp_addresses[55]=0x00000000004030d0;
    vuln.bp_addresses[56]=0x000000000040d8a0;
    vuln.bp_addresses[57]=0x000000000040d800;
    vuln.bp_addresses[58]=0x000000000040d790;
    vuln.bp_addresses[59]=0x0000000000402f50;
    vuln.bp_addresses[60]=0x000000000040da70;
    vuln.bp_addresses[61]=0x000000000040ef90;
    vuln.bp_addresses[62]=0x000000000040dbe0;
    vuln.bp_addresses[63]=0x000000000040db70;
    vuln.bp_addresses[64]=0x000000000040db00;
    vuln.bp_addresses[65]=0x0000000000403090;
    vuln.bp_addresses[66]=0x0000000000403220;
    vuln.bp_addresses[67]=0x0000000000403190;
    vuln.bp_addresses[68]=0x000000000040eec0;
    vuln.bp_addresses[69]=0x000000000040ee60;
    vuln.bp_addresses[70]=0x0000000000404690;
    vuln.bp_addresses[71]=0x0000000000403310;
    vuln.bp_addresses[72]=0x00000000004041e0;
    vuln.bp_addresses[73]=0x0000000000404240;
    vuln.bp_addresses[74]=0x0000000000404270;
    vuln.bp_addresses[75]=0x00000000004042a0;
    vuln.bp_addresses[76]=0x00000000004041b0;
    vuln.bp_addresses[77]=0x0000000000404730;
    vuln.bp_addresses[78]=0x00000000004042b0;
    vuln.bp_addresses[79]=0x00000000004046b0;
    vuln.bp_addresses[80]=0x0000000000404700;
    vuln.bp_addresses[81]=0x00000000004032d0;
    vuln.bp_addresses[82]=0x0000000000400bb0;
    vuln.bp_addresses[83]=0x0000000000403170;
    vuln.bp_addresses[84]=0x0000000000408020;
    vuln.bp_addresses[85]=0x0000000000406510;
    vuln.bp_addresses[86]=0x000000000040d930;
    vuln.bp_addresses[87]=0x0000000000403140;
    vuln.bp_addresses[88]=0x0000000000408190;
    vuln.bp_addresses[89]=0x0000000000404740;
    vuln.bp_addresses[90]=0x0000000000402f30;
    vuln.bp_addresses[91]=0x000000000040d7a0;
    vuln.bp_addresses[92]=0x0000000000402f60;
    vuln.bp_addresses[93]=0x0000000000402f00;
    vuln.bp_addresses[94]=0x0000000000402ef0;
    vuln.bp_addresses[95]=0x0000000000410aa0;
    vuln.bp_addresses[96]=0x0000000000410060;
    vuln.bp_addresses[97]=0x0000000000410510;
    vuln.bp_addresses[98]=0x0000000000410100;
    vuln.bp_addresses[99]=0x0000000000410200;
    vuln.bp_addresses[100]=0x0000000000410330;
    vuln.bp_addresses[101]=0x00000000004103e0;
    vuln.bp_addresses[102]=0x000000000040fdf0;
    vuln.bp_addresses[103]=0x000000000040fdb0;
    vuln.bp_addresses[104]=0x000000000040fdc0;
    vuln.bp_addresses[105]=0x0000000000402fd0;
    vuln.bp_addresses[106]=0x000000000040fdd0;
    vuln.bp_addresses[107]=0x000000000040fde0;
    vuln.bp_addresses[108]=0x000000000040fda0;
    vuln.bp_addresses[109]=0x000000000040fd00;
    vuln.bp_addresses[110]=0x000000000040ff20;
    vuln.bp_addresses[111]=0x0000000000403030;
    vuln.bp_addresses[112]=0x000000000040fe60;
    vuln.bp_addresses[113]=0x0000000000402fe0;
    vuln.bp_addresses[114]=0x0000000000402fb0;
    vuln.bp_addresses[115]=0x0000000000402f80;
    vuln.bp_addresses[116]=0x000000000040d8d0;
    vuln.bp_addresses[117]=0x0000000000411260;
    vuln.bp_addresses[118]=0x0000000000402f10;
    vuln.bp_addresses[119]=0x0000000000411fa0;
    vuln.bp_addresses[120]=0x0000000000412040;
    vuln.bp_addresses[121]=0x00000000004120c0;
    vuln.bp_addresses[122]=0x00000000004110e0;
    vuln.bp_addresses[123]=0x0000000000411f00;
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

    memcpy(input_prototype,"\x1\x1\x1\x1\x1\x1\x1\x1\x1\x1\x1\x1",12);
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

