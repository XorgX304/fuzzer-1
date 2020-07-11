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

#include "string.h"
#include "stdio.h"
#include "stdlib.h"
#include "unistd.h"

#include <oniguruma.h>
int main(int argc, char** argv) {
    OnigUChar inp[] =  {1,1,1,1,1,1,0,0,0,0,0,0};

    regex_t *reg;
    printf("myar ptr:%p\n",&inp);
    printf("myar:%s\n",&inp);

    onig_new
        (&reg,&inp,&inp+12,ONIG_OPTION_IGNORECASE , ONIG_ENCODING_UTF32_BE,
         ONIG_SYNTAX_DEFAULT, 0);
    onig_free(reg);
     printf("myar ptr:%p\n",&inp);
    printf("myar:%s\n",&inp);


    printf("end");
    return 0;

}

