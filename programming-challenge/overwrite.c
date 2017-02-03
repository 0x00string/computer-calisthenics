#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

unsigned int overwriteMe(void) {
    return(0);
}

unsigned int rewrite(void){
    unsigned int pgsz;
    unsigned char *ptr;
    unsigned int off;
    pgsz = getpagesize(); // get page size
    off = ( unsigned int )( ( ( long ) overwriteMe ) & ( pgsz - 1 ) ); // get offset of overwriteMe
    ptr = ( unsigned char * ) ( ( long ) overwriteMe & ( ~ ( pgsz - 1 ) ) ); // get a pointer to overwriteMe
    if ( mprotect( ptr, pgsz, PROT_READ|PROT_EXEC|PROT_WRITE ) ) { // modify permissions for pgsz region of memory starting at overwriteMe
            printf("mprotect fail");
            return(1);
    }
    ptr[off+0]=0xb8;	//	mov eax,0x01
    ptr[off+1]=0x01;
    ptr[off+2]=0x00;
    ptr[off+3]=0x00;
    ptr[off+4]=0x00;
    ptr[off+5]=0xc3;	//	ret
}

int main(void){
    unsigned int ret;		//create unsigned int to hold return value from overwriteMe
    ret = overwriteMe();	//get first value, 0
    printf("0x%02X\n",ret);
    rewrite();			//call rewrite
    ret = overwriteMe();	//get new value, 1
    printf("0x%02X\n",ret);
    exit(0);
}
