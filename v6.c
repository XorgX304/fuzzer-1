#include "string.h"
#include "stdio.h"
#include "stdlib.h"
#include "unistd.h"

#include <oniguruma.h>
int main(int argc, char** argv) {
     unsigned char myar[12] = {1,1,1,1,1,1,0,0,0,0,0,0};
    
    regex_t *reg;
    printf("myar ptr:%p\n",&myar);
    printf("myar:%s\n",myar);

    onig_new
        (&reg,&myar, &myar+12,ONIG_OPTION_IGNORECASE , ONIG_ENCODING_UTF32_BE,
          ONIG_SYNTAX_DEFAULT, 0);
    onig_free(reg);

    printf("end");

}

