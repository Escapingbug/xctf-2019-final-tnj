#include <unistd.h>
#include <stdio.h>

struct shellcode {
    unsigned int size;
    unsigned int loc;
    char *code;
};

char defender_shellcode[] = "N\xf8\x00\x00";

void gen_defender(int *pipe, struct shellcode* _attacker) {
    int size = 4;
    puts("[+]");
    write(pipe[1], &size, sizeof(int));

    write(pipe[1], defender_shellcode, size);
}
