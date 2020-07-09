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

    printf("end");
    return 0;

}

