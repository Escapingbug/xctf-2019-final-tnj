#include "arg.h"
#include <stdlib.h>

struct config get_config(void) {
    struct config config;
    config.attacker_size = 0x300;
    config.arena_size = 0x300;
    config.defender_size = 0x1000;
    config.steps_per_round = 1;
    config.steps_to_win = 0x1000;
    return config;
}
