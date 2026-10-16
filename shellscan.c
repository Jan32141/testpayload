/* Scan SceShellUI process and related binaries for devkit panel references.
 * Searches loaded modules on disk and tries to read process memory. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include <ps5/kernel.h>

#define OUT_DIR "/data/testpayload"

static void
elevate(void) {
  pid_t pid = getpid();
  kernel_set_ucred_uid(pid, 0);
  kernel_set_ucred_ruid(pid, 0);
  kernel_set_ucred_svuid(pid, 0);
  kernel_set_ucred_rgid(pid, 0);
  kernel_set_ucred_svgid(pid, 0);
  kernel_set_ucred_authid(pid, 0x4800000000010003UL);
  uint8_t fc[16]; memset(fc, 0xff, sizeof(fc));
  kernel_set_ucred_caps(pid, fc);
  uint8_t fa[32]; memset(fa, 0xff, sizeof(fa));
  kernel_set_ucred_attrs(pid, fa);
  intptr_t rv = kernel_get_root_vnode();
  if(rv) {
    kernel_set_proc_rootdir(pid, rv);
    kernel_set_proc_jaildir(pid, rv);
  }
  if(KERNEL_ADDRESS_PRISON0)
    kernel_set_ucred_prison(pid, KERNEL_ADDRESS_PRISON0);
}

static pid_t
find_process(const char *name) {
  int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
  size_t len = 0;
  if(sysctl(mib, 4, NULL, &len, NULL, 0)) return -1;
  char *buf = malloc(len);
  if(!buf) return -1;
  if(sysctl(mib, 4, buf, &len, NULL, 0)) { free(buf); return -1; }

  pid_t found = -1;
  size_t count = len / sizeof(struct kinfo_proc);
  struct kinfo_proc *procs = (struct kinfo_proc *)buf;
  for(size_t i = 0; i < count; i++) {
    if(strstr(procs[i].ki_comm, name)) {
      found = procs[i].ki_pid;
      break;
    }
  }
  free(buf);
  return found;
}

static void
hexdump_fp(FILE *fp, const unsigned char *data, size_t len, size_t base) {
  for(size_t i = 0; i < len; i += 16) {
    fprintf(fp, "    %08zx: ", base + i);
    for(size_t j = 0; j < 16 && (i+j) < len; j++)
      fprintf(fp, "%02x ", data[i+j]);
    for(size_t j = (len - i < 16 ? len - i : 16); j < 16; j++)
      fprintf(fp, "   ");
    fprintf(fp, " ");
    for(size_t j = 0; j < 16 && (i+j) < len; j++) {
      unsigned char c = data[i+j];
      fprintf(fp, "%c", (c >= 0x20 && c < 0x7f) ? c : '.');
    }
    fprintf(fp, "\n");
  }
}

static void
search_strings_in_data(FILE *fp, const unsigned char *data, size_t len,
                       const char *source, size_t base_offset) {
  const char *needles[] = {
    "devkit", "DevKit", "DEVKIT",
    "devpanel", "DevPanel",
    "overlay", "Overlay",
    "host_overlay",
    "debug_menu", "DebugMenu",
    "panel", "Panel",
    "testkit", "TestKit",
    "devenv", "DevEnv",
    "target_name", "TargetName",
    "show_mode", "ShowMode",
    "compositor", "Compositor",
    "shell_debug", "ShellDebug",
    "qaflag", "QAFlag",
    "disp_titleid",
    "content_info",
    "trc_notify",
    "host_name",
    "regId=0x78",
    "0x78020000",
    "0x7802",
    "sceRegMgr",
    NULL
  };

  for(int n = 0; needles[n]; n++) {
    size_t nlen = strlen(needles[n]);
    for(size_t i = 0; i + nlen <= len; i++) {
      if(!memcmp(&data[i], needles[n], nlen)) {
        fprintf(fp, "  \"%s\" in %s at offset 0x%zx\n",
                needles[n], source, base_offset + i);
        size_t ctx_start = (i >= 48) ? i - 48 : 0;
        size_t ctx_len = 128;
        if(ctx_start + ctx_len > len) ctx_len = len - ctx_start;
        hexdump_fp(fp, &data[ctx_start], ctx_len, base_offset + ctx_start);
      }
    }
  }
}

static void
scan_file_for_strings(FILE *fp, const char *path) {
  int fd = open(path, O_RDONLY);
  if(fd < 0) return;

  struct stat st;
  fstat(fd, &st);
  if(st.st_size > 50 * 1024 * 1024) { close(fd); return; }

  unsigned char *data = malloc(st.st_size);
  if(!data) { close(fd); return; }

  ssize_t total = 0;
  while(total < st.st_size) {
    ssize_t n = read(fd, data + total, st.st_size - total);
    if(n <= 0) break;
    total += n;
  }
  close(fd);

  search_strings_in_data(fp, data, total, path, 0);
  free(data);
}

static void
list_and_scan_dir(FILE *fp, const char *path, int depth) {
  DIR *d = opendir(path);
  if(!d) {
    fprintf(fp, "  %s: cannot open\n", path);
    return;
  }
  struct dirent *ent;
  while((ent = readdir(d))) {
    if(!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
      continue;
    char full[512];
    snprintf(full, sizeof(full), "%s/%s", path, ent->d_name);
    struct stat st;
    if(stat(full, &st)) continue;

    if(S_ISDIR(st.st_mode)) {
      fprintf(fp, "%*s%s/\n", depth*2, "", ent->d_name);
      if(depth < 2) list_and_scan_dir(fp, full, depth+1);
    } else {
      fprintf(fp, "%*s%s  (%ld bytes)\n", depth*2, "", ent->d_name, (long)st.st_size);
      /* scan shell-related sprx files and the shell executable */
      if(strstr(ent->d_name, "Shell") || strstr(ent->d_name, "shell") ||
         strstr(ent->d_name, "devkit") || strstr(ent->d_name, "Devkit") ||
         strstr(ent->d_name, "panel") || strstr(ent->d_name, "Panel") ||
         strstr(ent->d_name, "overlay") || strstr(ent->d_name, "Overlay") ||
         strstr(ent->d_name, "debug") || strstr(ent->d_name, "Debug") ||
         strstr(ent->d_name, "target") || strstr(ent->d_name, "Target")) {
        printf("shellscan: scanning %s...\n", full);
        scan_file_for_strings(fp, full);
      }
    }
  }
  closedir(d);
}

static void
try_vmmap(FILE *fp, pid_t pid) {
  fprintf(fp, "\n--- VMMAP for PID %d ---\n", pid);
  int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_VMMAP, pid };
  size_t len = 0;
  int err = sysctl(mib, 4, NULL, &len, NULL, 0);
  if(err) {
    fprintf(fp, "  sysctl KERN_PROC_VMMAP failed: %d\n", err);
    return;
  }
  char *buf = malloc(len);
  if(!buf) return;
  err = sysctl(mib, 4, buf, &len, NULL, 0);
  if(err) {
    fprintf(fp, "  sysctl read failed: %d\n", err);
    free(buf);
    return;
  }

  fprintf(fp, "  vmmap data: %zu bytes\n", len);
  struct kinfo_vmentry *entry = (struct kinfo_vmentry *)buf;
  int count = 0;
  char *pos = buf;
  while(pos < buf + len) {
    entry = (struct kinfo_vmentry *)pos;
    if(entry->kve_structsize == 0) break;

    const char *type = "?";
    switch(entry->kve_type) {
      case 1: type = "obj"; break;
      case 2: type = "swap"; break;
      case 3: type = "dev"; break;
      case 4: type = "phys"; break;
      case 5: type = "dead"; break;
      case 6: type = "sg"; break;
      case 7: type = "mgtdev"; break;
    }
    char prot[4] = "---";
    if(entry->kve_protection & 1) prot[0] = 'r';
    if(entry->kve_protection & 2) prot[1] = 'w';
    if(entry->kve_protection & 4) prot[2] = 'x';

    fprintf(fp, "  0x%012lx-0x%012lx %s %s",
            (unsigned long)entry->kve_start,
            (unsigned long)entry->kve_end,
            prot, type);
    if(entry->kve_path[0])
      fprintf(fp, "  %s", entry->kve_path);
    fprintf(fp, "\n");
    count++;

    pos += entry->kve_structsize;
  }
  fprintf(fp, "  total entries: %d\n", count);
  free(buf);
}

static void
try_ptrace_read(FILE *fp, pid_t pid) {
  fprintf(fp, "\n--- PTRACE memory scan for PID %d ---\n", pid);

  int err = ptrace(PT_ATTACH, pid, 0, 0);
  if(err) {
    fprintf(fp, "  PT_ATTACH failed: %d\n", err);
    return;
  }

  int status;
  waitpid(pid, &status, 0);
  fprintf(fp, "  attached, status=0x%x\n", status);

  /* get vmmap to know what to read */
  int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_VMMAP, pid };
  size_t len = 0;
  if(!sysctl(mib, 4, NULL, &len, NULL, 0)) {
    char *buf = malloc(len);
    if(buf && !sysctl(mib, 4, buf, &len, NULL, 0)) {
      char *pos = buf;
      int regions_scanned = 0;
      while(pos < buf + len && regions_scanned < 50) {
        struct kinfo_vmentry *e = (struct kinfo_vmentry *)pos;
        if(e->kve_structsize == 0) break;

        /* scan readable regions that might contain code/data */
        if((e->kve_protection & 1) && /* readable */
           e->kve_end > e->kve_start &&
           (e->kve_end - e->kve_start) <= 32 * 1024 * 1024) {
          size_t region_size = e->kve_end - e->kve_start;
          unsigned char *region = malloc(region_size);
          if(region) {
            struct ptrace_io_desc pio;
            pio.piod_op = PIOD_READ_D;
            pio.piod_offs = (void *)e->kve_start;
            pio.piod_addr = region;
            pio.piod_len = region_size;

            if(!ptrace(PT_IO, pid, (caddr_t)&pio, 0)) {
              char label[256];
              snprintf(label, sizeof(label), "mem[0x%lx-%lx %s]",
                       (unsigned long)e->kve_start,
                       (unsigned long)e->kve_end,
                       e->kve_path[0] ? e->kve_path : "anon");
              search_strings_in_data(fp, region, region_size,
                                    label, e->kve_start);
              regions_scanned++;
            }
            free(region);
          }
        }
        pos += e->kve_structsize;
      }
      fprintf(fp, "  scanned %d regions\n", regions_scanned);
    }
    free(buf);
  }

  ptrace(PT_DETACH, pid, (caddr_t)1, 0);
  fprintf(fp, "  detached\n");
}

int
main(void) {
  mkdir(OUT_DIR, 0777);
  elevate();
  printf("shellscan: elevated\n");

  FILE *fp;
  char path[256];
  snprintf(path, sizeof(path), "%s/shellscan.txt", OUT_DIR);
  fp = fopen(path, "w");
  if(!fp) { perror(path); return 1; }

  fprintf(fp, "=== SCESHELLUI DEVKIT PANEL SCAN ===\n\n");

  /* find SceShellUI */
  pid_t shell_pid = find_process("SceShellUI");
  fprintf(fp, "SceShellUI PID: %d\n\n", shell_pid);
  printf("shellscan: SceShellUI PID=%d\n", shell_pid);

  /* list all processes for context */
  fprintf(fp, "--- ALL PROCESSES ---\n");
  {
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t len = 0;
    if(!sysctl(mib, 4, NULL, &len, NULL, 0)) {
      char *buf = malloc(len);
      if(buf && !sysctl(mib, 4, buf, &len, NULL, 0)) {
        struct kinfo_proc *procs = (struct kinfo_proc *)buf;
        size_t count = len / sizeof(struct kinfo_proc);
        for(size_t i = 0; i < count; i++) {
          fprintf(fp, "  PID %5d  %s\n", procs[i].ki_pid, procs[i].ki_comm);
        }
        fprintf(fp, "  total: %zu\n", count);
      }
      free(buf);
    }
  }
  fprintf(fp, "\n");

  /* scan filesystem for shell/devkit related binaries */
  fprintf(fp, "--- FILESYSTEM SCAN ---\n");
  const char *scan_dirs[] = {
    "/system/common/lib",
    "/system/priv/lib",
    "/system/sys",
    "/system/vsh",
    "/system/vsh/app",
    "/system_ex/common_ex/lib",
    "/system_ex/app",
    "/system_ex/common_ex",
    "/system/common",
    NULL
  };
  for(int i = 0; scan_dirs[i]; i++) {
    fprintf(fp, "\n[%s]\n", scan_dirs[i]);
    list_and_scan_dir(fp, scan_dirs[i], 1);
  }
  fprintf(fp, "\n");

  /* try to get SceShellUI's vmmap */
  if(shell_pid > 0) {
    try_vmmap(fp, shell_pid);
    /* try ptrace-based memory scan */
    try_ptrace_read(fp, shell_pid);
  }

  /* also search for any config files related to devkit */
  fprintf(fp, "\n--- CONFIG FILE SEARCH ---\n");
  const char *config_dirs[] = {
    "/system_data/settings",
    "/system_data/priv/mms",
    "/data/system/common",
    "/system/common/conf",
    "/system/vsh/conf",
    NULL
  };
  for(int i = 0; config_dirs[i]; i++) {
    DIR *d = opendir(config_dirs[i]);
    if(!d) { fprintf(fp, "  %s: cannot open\n", config_dirs[i]); continue; }
    struct dirent *ent;
    fprintf(fp, "\n  [%s]\n", config_dirs[i]);
    while((ent = readdir(d))) {
      if(!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) continue;
      char full[512];
      snprintf(full, sizeof(full), "%s/%s", config_dirs[i], ent->d_name);
      struct stat st;
      if(!stat(full, &st) && S_ISREG(st.st_mode)) {
        fprintf(fp, "    %s (%ld bytes)\n", ent->d_name, (long)st.st_size);
        if(st.st_size < 1024 * 1024) {
          scan_file_for_strings(fp, full);
        }
      }
    }
    closedir(d);
  }

  fclose(fp);
  printf("shellscan: wrote %s\n", path);
  printf("shellscan: done\n");
  return 0;
}
