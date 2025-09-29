#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <haproxy/cfgparse.h>
#include "./src/cfgparse-tcp.c"

#ifndef __AFL_FUZZ_TESTCASE_LEN
ssize_t fuzz_len;
#define __AFL_FUZZ_TESTCASE_LEN fuzz_len
unsigned char fuzz_buf[1024000];
#define __AFL_FUZZ_TESTCASE_BUF fuzz_buf
#define __AFL_FUZZ_INIT() void sync(void);
#define __AFL_LOOP(x) ((fuzz_len = read(0, fuzz_buf, sizeof(fuzz_buf))) > 0 ? 1 : 0)
#define __AFL_INIT() sync()
#endif

int main(int argc, char **argv) {

#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif

  const char *buf = (const char *)__AFL_FUZZ_TESTCASE_BUF;

  while (__AFL_LOOP(10000)) {

    ssize_t len = __AFL_FUZZ_TESTCASE_LEN;
    char template[] = "/mnt/ramdisk/tmp/libfuzzerXXXXXX";
    int fd = mkstemp(template);

    if (fd == -1) {
        perror("Failed to create temporary file");
        continue;
    }
    
    write(fd, buf, len);
    close(fd);
    readcfgfile(template); // target function
    unlink(template);
  }
}
