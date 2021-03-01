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

#p = process("/opt/phoenix/amd64/net-zero")
p = remote("localhost", 64000)

print(p.recvline())
line = p.recvline()
request_value = line.split(" ")[2][1:-1]
print(request_value)

input_value = p32(int(request_value))
p.sendline(input_value)
p.interactive()
```

## After thought
pack vs unpack [from python3 doc](https://docs.python.org/3/library/struct.html)
```
 By default, the result of packing a given C struct includes pad bytes in order to maintain proper alignment for the C types involved; similarly, alignment is taken into account when unpacking. This behavior is chosen so that the bytes of a packed struct correspond exactly to the layout in memory of the corresponding C struct. To handle platform-independent data formats or omit implicit pad bytes, use standard size and alignment instead of native size and alignment: see Byte Order, Size, and Alignment for details.
 ```


# Net One
## Description

Link [https://exploit.education/phoenix/net-one/](https://exploit.education/phoenix/net-one/)
```c
/*
 * phoenix/net-one, by https://exploit.education
 *
 * Why aren't octal jokes funny?
 * Because 7 10 11
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
  uint32_t i;
  char buf[12], fub[12], *q;

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  printf("%s\n", BANNER);

  if (getrandom((void *)&i, sizeof(i), 0) != sizeof(i)) {
    errx(1, "unable to getrandom(%d bytes)", sizeof(i));
  }

  if (write(1, &i, sizeof(i)) != sizeof(i)) {
    errx(1, "unable to write %d bytes", sizeof(i));
  }

  if (fgets(buf, sizeof(buf), stdin) == NULL) {
    errx(1, "who knew that reading from stdin could be so difficult");
  }
  buf[sizeof(buf) - 1] = 0;

  q = strchr(buf, '\r');
  if (q) *q = 0;
  q = strchr(buf, '\n');
  if (q) *q = 0;

  sprintf(fub, "%u", i);
  if (strcmp(fub, buf) == 0) {
    printf("Congratulations, you've passed this level!\n");
  } else {
    printf("Close, you sent \"%s\", and we wanted \"%s\"\n", buf, fub);
  }

  return 0;
}
```

## Analyse
1. The random generated value is printed by `write()` in format of string, so we need to unpack the printed string into the original int number.

## Solution
```python
from pwn import *

#p = process("/opt/phoenix/amd64/net-one")
p = remote("localhost", 64001)
print(p.recvline())
request_value = p.recv()
print(request_value)

unpackaged = str(u32(request_value))
p.sendline(unpackaged)

p.interactive()
```

## After thought
pack vs unpack


