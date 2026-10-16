/* Kill SceShellUI — forces it to restart with a fresh compositor. */
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/sysctl.h>

int
main(void) {
  int mib[4] = {1, 14, 8, 0};
  size_t buf_size = 0;
  unsigned char *buf;
  pid_t mypid = getpid();

  if(sysctl(mib, 4, 0, &buf_size, 0, 0))
    return 1;
  buf = __builtin_alloca(buf_size);
  if(sysctl(mib, 4, buf, &buf_size, 0, 0))
    return 1;

  for(unsigned char *ptr = buf; ptr < (buf + buf_size);) {
    int ki_structsize = *(int*)ptr;
    pid_t ki_pid = *(pid_t*)&ptr[72];
    char *ki_tdname = (char*)&ptr[447];
    if(ki_structsize <= 0) break;
    if(ki_pid != mypid && !strcmp(ki_tdname, "SceShellUI")) {
      printf("killing SceShellUI (pid %d)...\n", ki_pid);
      kill(ki_pid, SIGKILL);
      printf("done\n");
      return 0;
    }
    ptr += ki_structsize;
  }

  printf("SceShellUI not found\n");
  return 1;
}
