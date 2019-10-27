#include <stdio.h>
#include <unistd.h>

struct shellcode {
    unsigned int size;
    unsigned int loc;
    char *code;
};

char clear_at[] = "\x20\x7c\x00\x00\x00\x00\x20\xfc\x00\x00\x00\x00";
char defender_shellcode[0x200];

//char tail_shellcode[] = "\x20\x7c\x00\x00\x00\x00\x20\x3c\x00\x00\x03\x00\x20\xf8\x00\x00\xb0\x48\x6c\xec\x4e\xf9\x00\x80\x00\x0c";
char tail_shellcode[] = "\x20\x7c\x00\x00\x00\x00\x20\xfc\x00\x00\x00\x00\x4e\xf9\x00\x80\x00\x06";

void gen_defender(int *pipe, struct shellcode* _attacker) {
    int size = 0;
    for (unsigned int i = 0; i < _attacker->size - 3; i++) {
        if (_attacker->code[i] == (char)0x4e && _attacker->code[i + 1] == (char)0xf8) {
            // jmp xxxx
            clear_at[4] = _attacker->code[i + 2];
            clear_at[5] = _attacker->code[i + 3];
            for (int j = 0; j < 12; ++j) {
                defender_shellcode[size++] = clear_at[j];
            }
        }
    }
    for (int i = 0; i < 18; ++i) {
        defender_shellcode[size++] = tail_shellcode[i];
    }
    write(pipe[1], &size, sizeof(int));

    write(pipe[1], defender_shellcode, size);
}
