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

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {

  #ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
  #endif

  const char *buf = (const char *)__AFL_FUZZ_TESTCASE_BUF;

  while (__AFL_LOOP(10000)) {

      ssize_t len = __AFL_FUZZ_TESTCASE_LEN;

      char filename[256];
      sprintf(filename, "/mnt/ramdisk/tmp/libfuzzercfg.%d", getpid());

      FILE *fp = fopen(filename, "wb");
      if (!fp) {
        continue; 
      }

      fwrite(buf, len, 1, fp);
      fclose(fp);
      
      readcfgfile(filename); //target function
      
      unlink(filename);
  }
}
