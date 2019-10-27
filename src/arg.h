#ifndef _ARG_H
#define _ARG_H

struct config {
    int attacker_size;
    int arena_size;
    int defender_size;
    int steps_per_round;
    int steps_to_win;
};

/* this is designed to be modifiable according to attacker
 * and defender's points and the time passed, but not
 * implemented eventually */
struct config get_config(void);

#endif
