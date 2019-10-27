
#include <unistd.h>

struct shellcode {
    unsigned int size;
    unsigned int loc;
    char *code;
};

char defender_shellcode[] = "\x4e\xf9\x00\x80\x00\x00";

void gen_defender(int *pipe, struct shellcode* _attacker) {
    int size = 6;
    write(pipe[1], &size, sizeof(int));

    write(pipe[1], defender_shellcode, size);
}
