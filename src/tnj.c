#include <unicorn/unicorn.h>
#include "arg.h"
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <unistd.h>
//#include <linux/signal.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>

//#define CPU_TRACE
//#define TRACE

struct range {
    uint64_t begin;
    uint64_t end;
};

struct m68k_regs {
    int a[8];
    int d[8];
    int sr;
    int pc;
};

enum side {
    ATTACKER = 0,
    DEFENDER
};

struct shellcode {
    unsigned int size;
    unsigned int loc;
    char *code;
};

enum side current;
struct m68k_regs status[2];
struct config config;
int steps;
int steps_to_win;
uint64_t arena_map;
uint64_t defender_map;
uint64_t ensure_segfault_addr = 0x10000000;
struct range prevent_access_range;
char *flag;

typedef struct shellcode* (*gen_defender_fn)(int *pipe, struct shellcode *);

void raise_exception(void) {
    printf("fuck!\n");
}

#ifdef TRACE
static void do_save_regs(uc_engine *uc, struct m68k_regs *regs);

void trace(char * fmt, ...) {
    va_list myargs;
    va_start(myargs, fmt);
    printf("[TRACE]: ");
    vprintf(fmt, myargs);
    va_end(myargs);
}

#ifdef CPU_TRACE

void print_regs(uc_engine *uc) {
    struct m68k_regs regs;
    do_save_regs(uc, &regs);

    int bytes = 0;

    uc_err err;
    err = uc_mem_read(uc, regs.pc, &bytes, 4);
    if (err) {
        fprintf(stderr, "uc_mem_read: print regs");
        exit(1);
    }

    char attacker_s[] = "attacker";
    char defender_s[] = "defender";
    if (current == ATTACKER) {
    	printf("============= 0x%x (%s) =============\n", regs.pc, attacker_s);
    } else {
    	printf("============= 0x%x (%s) (step: %d) =============\n", regs.pc, defender_s, steps_to_win);
    }
    printf("current ins bytes: 0x%x\n", bytes);
    printf("a0 0x%x\n", regs.a[0]);
    printf("a1 0x%x\n", regs.a[1]);
    printf("a2 0x%x\n", regs.a[2]);
    printf("a3 0x%x\n", regs.a[3]);
    printf("a4 0x%x\n", regs.a[4]);
    printf("a5 0x%x\n", regs.a[5]);
    printf("a6 0x%x\n", regs.a[6]);
    printf("a7 0x%x\n", regs.a[7]);
    printf("---------------------\n");
    printf("d0 0x%x\n", regs.d[0]);
    printf("d1 0x%x\n", regs.d[1]);
    printf("d2 0x%x\n", regs.d[2]);
    printf("d3 0x%x\n", regs.d[3]);
    printf("d4 0x%x\n", regs.d[4]);
    printf("d5 0x%x\n", regs.d[5]);
    printf("d6 0x%x\n", regs.d[6]);
    printf("d7 0x%x\n", regs.d[7]);
    printf("----------------------\n");
    printf("pc 0x%x\n", regs.pc);
    printf("sr 0x%x\n", regs.sr);
}
#else
void print_regs(uc_engine *uc) {}
#endif

#else
void trace(char *fmt, ...) {}
#endif

static void do_save_regs(uc_engine *uc, struct m68k_regs *regs) {
    uc_reg_read(uc, UC_M68K_REG_A0, &regs->a[0]);
    uc_reg_read(uc, UC_M68K_REG_A1, &regs->a[1]);
    uc_reg_read(uc, UC_M68K_REG_A2, &regs->a[2]);
    uc_reg_read(uc, UC_M68K_REG_A3, &regs->a[3]);
    uc_reg_read(uc, UC_M68K_REG_A4, &regs->a[4]);
    uc_reg_read(uc, UC_M68K_REG_A5, &regs->a[5]);
    uc_reg_read(uc, UC_M68K_REG_A6, &regs->a[6]);
    uc_reg_read(uc, UC_M68K_REG_A7, &regs->a[7]);

    uc_reg_read(uc, UC_M68K_REG_D0, &regs->d[0]);
    uc_reg_read(uc, UC_M68K_REG_D1, &regs->d[1]);
    uc_reg_read(uc, UC_M68K_REG_D2, &regs->d[2]);
    uc_reg_read(uc, UC_M68K_REG_D3, &regs->d[3]);
    uc_reg_read(uc, UC_M68K_REG_D4, &regs->d[4]);
    uc_reg_read(uc, UC_M68K_REG_D5, &regs->d[5]);
    uc_reg_read(uc, UC_M68K_REG_D6, &regs->d[6]);
    uc_reg_read(uc, UC_M68K_REG_D7, &regs->d[7]);

    uc_reg_read(uc, UC_M68K_REG_PC, &regs->pc);
    uc_reg_read(uc, UC_M68K_REG_SR, &regs->sr);
}

static void save_regs(uc_engine *uc, enum side side) {
    do_save_regs(uc, &status[side]);
}


static void restore_regs(uc_engine *uc, enum side side) {
    uc_reg_write(uc, UC_M68K_REG_A0, &status[side].a[0]);
    uc_reg_write(uc, UC_M68K_REG_A1, &status[side].a[1]);
    uc_reg_write(uc, UC_M68K_REG_A2, &status[side].a[2]);
    uc_reg_write(uc, UC_M68K_REG_A3, &status[side].a[3]);
    uc_reg_write(uc, UC_M68K_REG_A4, &status[side].a[4]);
    uc_reg_write(uc, UC_M68K_REG_A5, &status[side].a[5]);
    uc_reg_write(uc, UC_M68K_REG_A6, &status[side].a[6]);
    uc_reg_write(uc, UC_M68K_REG_A7, &status[side].a[7]);

    uc_reg_write(uc, UC_M68K_REG_D0, &status[side].d[0]);
    uc_reg_write(uc, UC_M68K_REG_D1, &status[side].d[1]);
    uc_reg_write(uc, UC_M68K_REG_D2, &status[side].d[2]);
    uc_reg_write(uc, UC_M68K_REG_D3, &status[side].d[3]);
    uc_reg_write(uc, UC_M68K_REG_D4, &status[side].d[4]);
    uc_reg_write(uc, UC_M68K_REG_D5, &status[side].d[5]);
    uc_reg_write(uc, UC_M68K_REG_D6, &status[side].d[6]);
    uc_reg_write(uc, UC_M68K_REG_D7, &status[side].d[7]);

    uc_reg_write(uc, UC_M68K_REG_PC, &status[side].pc);
    uc_reg_write(uc, UC_M68K_REG_SR, &status[side].sr);
}


static void turn(void) {
    trace("--- turn ---\n");
    current ^= 1;
}

static int should_turn(void) {
    int turn = 0;
    if (steps <= 0) {
        turn = 1;
        steps = config.steps_per_round;
    }
    return turn;
}

static void auth_adjust(uc_engine *uc, enum side current) {
    /* if we are the attacker, don't allow access to defender code */
    if (current == ATTACKER) {
        uc_mem_protect(uc, defender_map, config.defender_size, UC_PROT_NONE);
    } else {
        /* we are the defender, we need to access it */
        uc_mem_protect(uc, defender_map, config.defender_size, UC_PROT_ALL);
    }
}

/* called every instruction step */
static void per_round(uc_engine *uc, uint64_t addr, uint32_t size, void *user_data) {
#ifdef TRACE
    print_regs(uc);    
#endif

    uint64_t pc;
    uc_reg_read(uc, UC_M68K_REG_PC, &pc);

    trace("pc: 0x%lx\n", pc);

    if (pc <= prevent_access_range.end && pc >= prevent_access_range.begin) {
        /* cause seg fault */
        trace("rewrite 0x%lx to 0x%lx\n", pc, ensure_segfault_addr);
        uc_reg_write(uc, UC_M68K_REG_PC, &ensure_segfault_addr);
        trace("rewrite done\n");
    }

    if (current == ATTACKER) {
        steps_to_win--;
    }
    if (should_turn()) {
        save_regs(uc, current);
        turn();
        restore_regs(uc, current);

        auth_adjust(uc, current);
    } else {
        steps--;
    }
}

static struct shellcode* get_attacker_shellcode(void) {
    struct shellcode *code = malloc(sizeof(struct shellcode));
    code->size = 0;

    printf("size > ");
    scanf("%u", &code->size);
    trace("size: %u\n", code->size);
    if (code->size < 0 || code->size >= config.attacker_size) {
        puts("too greedy");
        exit(1);
    }
    code->code = (char*) malloc(code->size);
    printf("code > ");
    int size_read = read(STDIN_FILENO, code->code, code->size);
    trace("size_read: %d\n", size_read);
    /* location is deferred to gather, to be sure defender cannot
     * get its info */
    code->loc = 0;

    return code;
}

static struct shellcode *attacker_shellcode_cont(struct shellcode *attacker) {
    /* complete interaction */
    printf("loc > ");
    scanf("%u", &attacker->loc);
    if (attacker->loc >= config.arena_size || attacker->loc + attacker->size >= config.arena_size) {
        printf("location out of bound\n");
        exit(0);
    }
    return attacker;
}

void sandbox_on(void) {
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT) < 0) {
        fprintf(stderr, "Failed to start sandbox\n");
        perror("prctl");
        exit(1);
    }
}

static struct shellcode* get_defender_shellcode(struct shellcode *attacker) {
    trace("get_defender_shellcode begin\n");
    void *defender_lib = dlopen("./defender.so", RTLD_NOW);
    if (defender_lib == NULL) {
        fprintf(stderr, "defender opening error with %s\n", dlerror());
        exit(1);
    }
    trace("defender_lib 0x%lx\n", (long) defender_lib);
    gen_defender_fn defender_func = (gen_defender_fn) dlsym(defender_lib, "gen_defender");
    trace("defender_func 0x%lx\n", (long) defender_func);
    if (defender_func == NULL) {
        fputs("defender is collapsed\n", stderr);
        exit(1);
    }
    int code_pipe[2];
    if (pipe(code_pipe) < 0) {
        fputs("unable to get pipe working\n", stderr);
        exit(1);
    }

    trace("before fork\n");

    pid_t pid = fork();

    if (pid == 0) {
        alarm(8);
        close(code_pipe[0]);
        trace("turning on sandbox\n");
        sandbox_on();
        trace("calling defender func\n");
        defender_func(code_pipe, attacker);
        trace("calling defender func done\n");
        exit(0);
    } else {
        close(code_pipe[1]);
        int wstatus;
        wait(&wstatus);
        trace("status %x sig %d \n", WEXITSTATUS(wstatus), WTERMSIG(wstatus));
        if (WEXITSTATUS(wstatus) != 0 || WTERMSIG(wstatus) == SIGSEGV) {
            printf("defender crashed, your gift: %s\n", flag);
            exit(1);
        }
    }

    unsigned int defender_shellcode_size = 0;
    int size_read = read(code_pipe[0], &defender_shellcode_size, sizeof(int));
    trace("get size 0x%x\n", size_read);
    trace("defender wrote size 0x%x\n", defender_shellcode_size);


    if (defender_shellcode_size >= config.defender_size) {
        fprintf(stderr, "defender too long");
        exit(1);
    }

    struct shellcode *defender = (struct shellcode *) malloc(sizeof(struct shellcode));
    defender->code = (char *) malloc(defender_shellcode_size);
    defender->size = defender_shellcode_size;
    read(code_pipe[0], defender->code, defender_shellcode_size);
    close(code_pipe[0]);

    dlclose(defender_lib);

#ifdef TRACE
    trace("defender code:\n");
    for (unsigned int i = 0; i < defender_shellcode_size; ++i) {
	printf("0x%x ", defender->code[i] & 0xff);
	if (i % 0x10 == 0) {
		printf("\n");
	}
    }
    printf("\n");
#endif

    return defender;
}

static void prevent_access(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data) {
    trace("accessing 0x%lx prevented\n", address);
    uc_reg_write(uc, UC_M68K_REG_PC, &ensure_segfault_addr);
}

static void allocate_map(uc_engine *uc) {
    uc_err err;
    uc_hook prevent;
    arena_map = 0;
    defender_map = 0x800000;
    if (config.arena_size < 0x1000) {
        err = uc_mem_map(uc, arena_map, 0x1000, UC_PROT_ALL);
        if (err) {
            fprintf(stderr, "uc_mem_map arena error");
            exit(1);
        }
        prevent_access_range.begin = config.arena_size + arena_map;
        prevent_access_range.end = 0x1000 + arena_map;
        trace("setup trace hook from 0x%lx to 0x%lx\n", 
            prevent_access_range.begin, prevent_access_range.end);
        err = uc_hook_add(
            uc, 
            &prevent, 
            UC_HOOK_MEM_READ, 
            prevent_access, 
            NULL, 
            prevent_access_range.begin,
            prevent_access_range.end);
        if (err) {
            fprintf(stderr, "add preventing hook error");
            exit(1);
        }
        err = uc_hook_add(
            uc, 
            &prevent, 
            UC_HOOK_MEM_WRITE, 
            prevent_access, 
            NULL, 
            prevent_access_range.begin,
            prevent_access_range.end);
        if (err) {
            fprintf(stderr, "add preventing hook error");
            exit(1);
        }
    } else {
        err = uc_mem_map(uc, arena_map, config.arena_size, UC_PROT_ALL);
        if (err) {
            fprintf(stderr, "uc_mem_map arena error, wtf?\n");
            exit(1);
        }
    }
    err = uc_mem_map(uc, defender_map, config.defender_size, UC_PROT_ALL);
    if (err) {
        fprintf(stderr, "uc_mem_map defender error, wtf?\n");
        exit(1);
    }
}

static void init_map(uc_engine *uc) {
    struct shellcode *attacker, *defender;
    trace("init_map begin\n");
    attacker = get_attacker_shellcode();
    trace("get_attacker_shellcode done\n");
    defender = get_defender_shellcode(attacker);
    trace("get_defender_shellcode done\n");
    attacker_shellcode_cont(attacker);

    if (uc_mem_write(uc, arena_map + attacker->loc, attacker->code, attacker->size) != 0) {
        fprintf(stderr, "unable to write attacker code");
        exit(1);
    }

    trace("write defender_map 0x%x with size 0x%x code %s\n",
            defender_map,
            defender->size,
            defender->code);
    if (uc_mem_write(uc, defender_map, defender->code, defender->size) != 0) {
        fprintf(stderr, "unable to write defender code");
        exit(1);
    }

    status[DEFENDER].pc = defender_map;
    status[ATTACKER].pc = attacker->loc + arena_map;
}

/*
 * jobs for init:
 * 
 * - open unicorn engine
 * - map unicorn memory
 * - get shellcode from the attacker
 * - get initial position of the attacker
 * - let defender run through the attacker's code, and get defender's shellcode
 * - map shellcode
 * - set defender and attacker's pc
 */
static uc_engine* init_game(void) {
    /* open uc engine */
    trace("init_game\n");
    uc_engine *uc;
    uc_err err;
    uc_hook round_hook;
    err = uc_open(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, &uc);
    if (err) {
        fputs("unable to uc_open", stderr);
        exit(1);
    }

    /* allocate mapping */
    allocate_map(uc);
    /* initialize map with attacker and defender, pc is changed within */
    init_map(uc);
    /* initialize steps */
    steps = config.steps_per_round;
    /* add round function */
    uc_hook_add(uc, &round_hook, UC_HOOK_CODE, per_round, NULL, 1, 0);
    /* setup current side, we run attacker first */
    current = ATTACKER;
    steps_to_win = config.steps_to_win;

    return uc;
}

static enum side run_game(uc_engine *uc) {
    uc_err err;

    trace("emu start\n");
    printf("[*] Let's head to it!\n");

    /*                       start         end(ignore) time(unlimited) inses */
    err = uc_emu_start(uc, status[current].pc, 0xffffffff, 0,               config.steps_to_win * 2 + 1);
    trace("emu start done current %d is defender crashed %d\n", current, current == DEFENDER);
    if (err) {
        trace("uc_emu_start error with %u\n", err);
    }
    if (steps_to_win <= 0 || current == DEFENDER) {
        return ATTACKER;
    } else {
        return DEFENDER;
    }
}

int main(int argc, char **argv) {
#ifndef TRACE
    alarm(10);
#endif
    trace("prog %s starts\n", argv[0]);
    if (argc < 2) {
        fprintf(stderr, "Usage: %s FLAG_PATH\n", argv[0]);
        return 1;
    }
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    FILE *f = fopen(argv[1], "r");
    if (f == NULL) {
        fprintf(stderr, "unable to open flag\n");
        return 1;
    }
    fseek(f, 0, SEEK_END);
    int file_size = ftell(f) * sizeof(char);
    flag = malloc(file_size);
    rewind(f);
    memset(flag, 0, file_size);
    int read_size = fread(flag, 1, file_size, f);
    if (read_size != file_size) {
        fputs("unable to read full flag, wtf?", stderr);
        return 1;
    }
    fclose(f);

    config = get_config();

    uc_engine *uc = init_game();
    trace("init_game done\n");
    enum side winner = run_game(uc);
    printf("[+] Run complete, winner %d is attacker %d\n", winner, winner == ATTACKER);
    if (winner == ATTACKER) {
        printf("%s\n", flag);
    }
    uc_close(uc);
    free(flag);
    trace("done");
    return 0;
}
