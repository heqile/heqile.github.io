---
layout: post
title:  "Phoenix Net"
date:   2021-03-01 00:00:00 +0000
categories: ExploitEducation
---
# Net Zero
## Description

Link [https://exploit.education/phoenix/net-zero/](https://exploit.education/phoenix/net-zero/)
```c
/*
 * phoenix/net-zero, by https://exploit.education
 *
 * What did the fish say when he swam head first into a wall?
 * Dam!
 */

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/types.h>
#include <unistd.h>

#define BANNER \
  "Welcome to " LEVELNAME ", brought to you by https://exploit.education"

int main(int argc, char **argv) {
  uint32_t i, j;

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  printf("%s\n", BANNER);

  if (getrandom((void *)&i, sizeof(i), 0) != sizeof(i)) {
    errx(1, "unable to getrandom(%d bytes)", sizeof(i));
  }

  printf("Please send '%u' as a little endian, 32bit integer.\n", i);

  if (read(0, (void *)&j, sizeof(j)) != sizeof(j)) {
    errx(1, "unable to read %d bytes from stdin", sizeof(j));
  }

  if (i == j) {
    printf("You have successfully passed this level, well done!\n");
  } else {
    printf("Close - you sent %u instead\n", j);
  }

  return 0;
}
```

## Analyse
1. The getrandom() generate a random number, and it will print the value. When we send the answer, it is an string which need to be convert when the server recieves. For example, 1145258561 -> 0x44434241 -> "ABCD"

## Solution
```python
from pwn import *

p = process("/opt/phoenix/amd64/net-zero")

print(p.recvline())
line = p.recvline()
request_value = line.split(" ")[2][1:-1]
print(request_value)

input_value = p32(int(request_value))
p.sendline(input_value)
p.interactive()
```

## Reflection
p32 / u32 - p64 / u64

