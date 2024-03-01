#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void not_called() {
    asm ("li a7, 221");                
    asm ("ecall");                     
    return;
}

int test_empty2() {
    asm ("li s1, 0x68732f6e69622f");   //hex of string /bin/bash
    asm ("sd s1, -16(sp)");            
    asm ("addi a0,sp,-16");           
    asm ("slt a1,zero,-1");            
    asm ("slt a2,zero,-1");            
    asm ("jal ra, 0x10506");
    return 1;
}

void test_empty() {
   puts("Test empty");
   return;
}

void vulnerable_function(char* string) {
    char buffer[100];
    strcpy(buffer, string);
}

int main(int argc, char** argv) {
    test_empty();
    vulnerable_function(argv[1]);
    return 0;
}
