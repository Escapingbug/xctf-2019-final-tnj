# tnj (Public)

## Challenge Info (Public)

Guess what is T & J?

## Deployment

[Unicorn Engine](https://github.com/unicorn-engine/unicorn) must be installed and usable (may require `LD_LIBRARY_PATH` modification so binary can find it as I tested it).

## Checking

The patch will directly replace original `defender.so` binary, no bytes checking needed.

`check.py` is in `src/test`, which only checks for start and ends of the simulation procedure. IO is checked to be complete, since I ensure it to be the end after "[+]".

## Intention

Tom and Jerry, Game.

Game is obvious, each turn one instruction will be executed as attacker or defender. Defender inspects attacker's shellcode, and generate shellcode accordingly.

When attacker survives, or defender crashes, attacker win. When attacker crashes, defender win.

Args are intentionally left modifiable, after some hours, the args may change. However, during the game, it is not modified at all.

So, defenders analyze attakcers' shellcode, and deal with it, to make it crash. 

## Expectation

1. Step 0: reverse engineering to get the semantic, trivial input triggers flag output which makes players' nerves tense.
2. Step 1: patch the original one, to make it fully working as a infinite loop. So, trivial input will not give out flag after.
3. Step 2: attackers improve to be infinite loop.
4. Step 3: defenders improve to overwrite the whole arena.
5. Step 4: attackers improve to copy itself to avoid overwrite
6. Step 6: defenders improve to analyze attackers' shellcode
7. ...
