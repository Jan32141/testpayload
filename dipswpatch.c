/* DIP switch reader + process-level patch to enable devkit panel.
 * Strategy:
 * 1. Read DIP switches via /dev/dipsw ioctl
 * 2. Dump memory around SECURITY_FLAGS/TARGETID (safe, small reads)
 * 3. Patch sceKernelIsDevKit/IsTestKit/IsCEX stubs in SceShellUI + SceShellCore
 * 4. Scan SceShellCore eboot for compositor profiler string
 *
 * SAFETY: NO kernel text scanning (caused kernel panic).
 *         NEVER touches IDU mode. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/types.h>

#include <ps5/kernel.h>

#define OUT_DIR "/data/testpayload"

int sceKernelGetProcessName(pid_t, char *);
int sceKernelIsDevKit(void);
int sceKernelIsTestKit(void);
int sceKernelIsCEX(void);

int sceRegMgrGetInt(unsigned int regId, int *value);
int sceRegMgrSetInt(unsigned int regId, int value);

#define DIPSW_IOCTL_READ(idx)  _IOR('d', (idx), uint32_t)

typedef struct notify_request {
  char unused[45];
  char message[3075];
} notify_request_t;
int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);

static void
notify(const char* msg) {
  notify_request_t req;
  memset(&req, 0, sizeof(req));
  strncpy(req.message, msg, sizeof(req.message) - 1);
  sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

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
  for(pid_t p = 0; p < 2000; p++) {
    intptr_t proc_addr = kernel_get_proc(p);
    if(!proc_addr) continue;
    char pname[64] = {0};
    if(!sceKernelGetProcessName(p, pname) && strstr(pname, name))
      return p;
  }
  return -1;
}

/* Phase 1: Read DIP switches - only the safe _IOR method */
static void
read_dipsw(FILE *fp) {
  fprintf(fp, "=== DIP SWITCH DUMP ===\n\n");
  printf("dipswpatch: reading DIP switches...\n");

  int fd = open("/dev/dipsw", O_RDONLY);
  if(fd < 0) {
    fprintf(fp, "  /dev/dipsw: cannot open (err=%d)\n", fd);
    printf("dipswpatch: cannot open /dev/dipsw\n");
    return;
  }

  fprintf(fp, "  /dev/dipsw opened (fd=%d)\n\n", fd);

  fprintf(fp, "  --- _IOR('d', idx, uint32_t) ---\n");
  int found_any = 0;
  for(int idx = 0; idx < 256; idx++) {
    uint32_t val = 0;
    int err = ioctl(fd, DIPSW_IOCTL_READ(idx), &val);
    if(!err) {
      if(val != 0 || idx < 16) {
        fprintf(fp, "  dipsw[0x%02x] = 0x%08x (%u)\n", idx, val, val);
        found_any = 1;
      }
    } else if(idx < 16) {
      fprintf(fp, "  dipsw[0x%02x] = ioctl failed (err=%d)\n", idx, err);
    }
  }

  if(!found_any)
    fprintf(fp, "  No DIP switch values read via _IOR\n");

  close(fd);
}

/* Phase 2: Dump kernel data around SECURITY_FLAGS/TARGETID
 * Uses only kernel_getchar/kernel_copyout on known-valid addresses.
 * NO kernel text scanning. */
static void
dump_kernel_flags(FILE *fp) {
  fprintf(fp, "\n=== KERNEL FLAGS DUMP ===\n\n");

  intptr_t sf_addr = KERNEL_ADDRESS_SECURITY_FLAGS;
  intptr_t tid_addr = KERNEL_ADDRESS_TARGETID;

  fprintf(fp, "  SECURITY_FLAGS @ 0x%lx = 0x%02x\n",
          (unsigned long)sf_addr, kernel_getchar(sf_addr));
  fprintf(fp, "  TARGETID @ 0x%lx = 0x%02x\n",
          (unsigned long)tid_addr, kernel_getchar(tid_addr));

  fprintf(fp, "  sceKernelIsDevKit()  = %d\n", sceKernelIsDevKit());
  fprintf(fp, "  sceKernelIsTestKit() = %d\n", sceKernelIsTestKit());
  fprintf(fp, "  sceKernelIsCEX()     = %d\n", sceKernelIsCEX());

  /* Safe: dump 256 bytes around SECURITY_FLAGS (kernel data, not text) */
  if(sf_addr) {
    intptr_t start = sf_addr - 64;
    unsigned char buf[256];
    int err = kernel_copyout(start, buf, sizeof(buf));
    if(!err) {
      fprintf(fp, "\n  Memory around SECURITY_FLAGS (-64 to +192):\n");
      for(int i = 0; i < 256; i += 16) {
        fprintf(fp, "    0x%lx: ", (unsigned long)(start + i));
        for(int j = 0; j < 16; j++)
          fprintf(fp, "%02x ", buf[i+j]);
        fprintf(fp, " ");
        for(int j = 0; j < 16; j++) {
          unsigned char c = buf[i+j];
          fprintf(fp, "%c", (c >= 0x20 && c < 0x7f) ? c : '.');
        }
        fprintf(fp, "\n");
      }
    } else {
      fprintf(fp, "  kernel_copyout around SF failed: %d\n", err);
    }
  }

  /* Also dump around TARGETID */
  if(tid_addr && tid_addr != sf_addr) {
    intptr_t start = tid_addr - 64;
    unsigned char buf[256];
    int err = kernel_copyout(start, buf, sizeof(buf));
    if(!err) {
      fprintf(fp, "\n  Memory around TARGETID (-64 to +192):\n");
      for(int i = 0; i < 256; i += 16) {
        fprintf(fp, "    0x%lx: ", (unsigned long)(start + i));
        for(int j = 0; j < 16; j++)
          fprintf(fp, "%02x ", buf[i+j]);
        fprintf(fp, " ");
        for(int j = 0; j < 16; j++) {
          unsigned char c = buf[i+j];
          fprintf(fp, "%c", (c >= 0x20 && c < 0x7f) ? c : '.');
        }
        fprintf(fp, "\n");
      }
    }
  }
}

/* Phase 3: Patch sceKernelIsDevKit/IsTestKit/IsCEX in process memory */
static int
patch_process_stubs(FILE *fp, pid_t pid, const char *pname) {
  fprintf(fp, "\n=== PATCH %s (PID %d) ===\n\n", pname, pid);

  uint32_t lk_handle = 0;
  if(kernel_dynlib_handle(pid, "libkernel_sys.sprx", &lk_handle)) {
    fprintf(fp, "  ERROR: can't get libkernel_sys handle\n");
    return -1;
  }
  fprintf(fp, "  libkernel_sys.sprx handle=0x%x\n", lk_handle);

  intptr_t base = kernel_dynlib_mapbase_addr(pid, lk_handle);
  fprintf(fp, "  libkernel_sys base=0x%lx\n", (unsigned long)base);

  intptr_t isdevkit_addr = kernel_dynlib_dlsym(pid, lk_handle, "sceKernelIsDevKit");
  intptr_t istestkit_addr = kernel_dynlib_dlsym(pid, lk_handle, "sceKernelIsTestKit");
  intptr_t iscex_addr = kernel_dynlib_dlsym(pid, lk_handle, "sceKernelIsCEX");

  fprintf(fp, "  sceKernelIsDevKit  @ 0x%lx\n", (unsigned long)isdevkit_addr);
  fprintf(fp, "  sceKernelIsTestKit @ 0x%lx\n", (unsigned long)istestkit_addr);
  fprintf(fp, "  sceKernelIsCEX     @ 0x%lx\n", (unsigned long)iscex_addr);

  int patched = 0;

  if(isdevkit_addr) {
    unsigned char orig[16];
    kernel_proc_copyout(pid, isdevkit_addr, orig, 16);
    fprintf(fp, "  Original IsDevKit:  ");
    for(int j = 0; j < 16; j++) fprintf(fp, "%02x ", orig[j]);
    fprintf(fp, "\n");

    int prot = kernel_get_vmem_protection(pid, isdevkit_addr, 16);
    fprintf(fp, "  Protection: 0x%x\n", prot);

    int mp = kernel_set_vmem_protection(pid, isdevkit_addr, 4096, 7);
    fprintf(fp, "  mprotect(rwx): %d\n", mp);

    unsigned char patch[] = { 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3 };
    int ret = kernel_proc_copyin(pid, patch, isdevkit_addr, 6);
    fprintf(fp, "  Patch IsDevKit -> return 1: %d\n", ret);

    unsigned char verify[16];
    kernel_proc_copyout(pid, isdevkit_addr, verify, 16);
    fprintf(fp, "  Verify:         ");
    for(int j = 0; j < 16; j++) fprintf(fp, "%02x ", verify[j]);
    fprintf(fp, "\n");

    if(ret == 0 && verify[0] == 0xb8 && verify[1] == 0x01)
      patched++;
  }

  if(istestkit_addr) {
    unsigned char orig[16];
    kernel_proc_copyout(pid, istestkit_addr, orig, 16);
    fprintf(fp, "\n  Original IsTestKit: ");
    for(int j = 0; j < 16; j++) fprintf(fp, "%02x ", orig[j]);
    fprintf(fp, "\n");

    kernel_set_vmem_protection(pid, istestkit_addr, 4096, 7);
    unsigned char patch[] = { 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3 };
    int ret = kernel_proc_copyin(pid, patch, istestkit_addr, 6);
    fprintf(fp, "  Patch IsTestKit -> return 1: %d\n", ret);
    if(ret == 0) patched++;
  }

  if(iscex_addr) {
    unsigned char orig[16];
    kernel_proc_copyout(pid, iscex_addr, orig, 16);
    fprintf(fp, "\n  Original IsCEX:     ");
    for(int j = 0; j < 16; j++) fprintf(fp, "%02x ", orig[j]);
    fprintf(fp, "\n");

    kernel_set_vmem_protection(pid, iscex_addr, 4096, 7);
    unsigned char patch[] = { 0x31, 0xc0, 0xc3 }; /* xor eax,eax; ret */
    int ret = kernel_proc_copyin(pid, patch, iscex_addr, 3);
    fprintf(fp, "  Patch IsCEX -> return 0: %d\n", ret);
    if(ret == 0) patched++;
  }

  fprintf(fp, "  Patched %d/%d stubs\n", patched, 3);
  return patched;
}

/* Phase 4: Scan SceShellCore eboot for compositor profiler string.
 * Limited to 16MB and bails on first all-zero chunk. */
static void
try_compositor_profiler(FILE *fp) {
  fprintf(fp, "\n=== COMPOSITOR ON-SCREEN PROFILER ===\n\n");

  pid_t sc_pid = find_process("SceShellCore");
  fprintf(fp, "  SceShellCore PID: %d\n", sc_pid);
  if(sc_pid < 0) return;

  /* List all libs we care about */
  const char *libs[] = {
    "eboot.bin",
    "libSceShellCoreUtil.sprx",
    NULL
  };

  for(int i = 0; libs[i]; i++) {
    uint32_t handle = 0;
    if(kernel_dynlib_handle(sc_pid, libs[i], &handle)) continue;

    intptr_t base = kernel_dynlib_mapbase_addr(sc_pid, handle);
    fprintf(fp, "  %s: handle=0x%x base=0x%lx\n",
            libs[i], handle, (unsigned long)base);

    /* Try symbol resolution */
    const char *syms[] = {
      "sceShellCoreUtilSetGnmCompositorOnScreenProfilerFlag",
      "sceShellCoreUtilGetGnmCompositorOnScreenProfilerFlag",
      NULL
    };
    for(int s = 0; syms[s]; s++) {
      intptr_t addr = kernel_dynlib_dlsym(sc_pid, handle, syms[s]);
      if(addr)
        fprintf(fp, "    %s = 0x%lx\n", syms[s], (unsigned long)addr);
    }
  }

  /* Scan eboot for the string */
  uint32_t eboot_handle = 0;
  if(kernel_dynlib_handle(sc_pid, "eboot.bin", &eboot_handle)) return;

  intptr_t base = kernel_dynlib_mapbase_addr(sc_pid, eboot_handle);
  if(!base) return;

  fprintf(fp, "\n  Scanning SceShellCore eboot for profiler strings...\n");

  size_t chunk_sz = 256 * 1024;
  unsigned char *buf = malloc(chunk_sz);
  if(!buf) return;

  const char *needles[] = {
    "GnmCompositorOnScreenProfiler",
    "QSP_set_host_system_info",
    "DevKit/TestKit successfully Activated",
    "devkit_panel",
    "DevKitPanel",
    "host_overlay",
    NULL
  };

  for(size_t off = 0; off < 16UL * 1024 * 1024; off += chunk_sz) {
    if(kernel_proc_copyout(sc_pid, base + off, buf, chunk_sz))
      break;

    /* Bail on all-zero */
    int all_zero = 1;
    for(size_t c = 0; c < 256; c++) {
      if(buf[c]) { all_zero = 0; break; }
    }
    if(all_zero) break;

    for(int n = 0; needles[n]; n++) {
      size_t nlen = strlen(needles[n]);
      for(size_t j = 0; j + nlen <= chunk_sz; j++) {
        if(!memcmp(&buf[j], needles[n], nlen)) {
          fprintf(fp, "    \"%s\" at 0x%lx\n",
                  needles[n], (unsigned long)(base + off + j));
        }
      }
    }
  }

  free(buf);
}

/* Phase 5: Also scan SceShellUI eboot for devkit-panel related strings */
static void
scan_shellui_devkit_strings(FILE *fp) {
  fprintf(fp, "\n=== SHELLUI DEVKIT PANEL STRINGS ===\n\n");

  pid_t pid = find_process("SceShellUI");
  if(pid < 0) return;

  uint32_t eboot_handle = 0;
  if(kernel_dynlib_handle(pid, "eboot.bin", &eboot_handle)) return;

  intptr_t base = kernel_dynlib_mapbase_addr(pid, eboot_handle);
  if(!base) return;

  fprintf(fp, "  SceShellUI eboot base: 0x%lx\n", (unsigned long)base);

  /* Also check the dipsw library */
  uint32_t dipsw_handle = 0;
  if(!kernel_dynlib_handle(pid, "libSceDipsw.sprx", &dipsw_handle)) {
    intptr_t dipsw_base = kernel_dynlib_mapbase_addr(pid, dipsw_handle);
    fprintf(fp, "  libSceDipsw.sprx: handle=0x%x base=0x%lx\n",
            dipsw_handle, (unsigned long)dipsw_base);

    /* Try to resolve dipsw symbols */
    const char *dsyms[] = {
      "sceDipswIsDevKit",
      "sceDipswIsTestKit",
      "sceDipswIsCEX",
      "sceDipswGetValue",
      "sceDipswGetFlag",
      "sceDipswSetFlag",
      "sceDipswClearFlag",
      "sceDipswInit",
      "sceDipswCheckDipsw",
      NULL
    };
    for(int s = 0; dsyms[s]; s++) {
      intptr_t addr = kernel_dynlib_dlsym(pid, dipsw_handle, dsyms[s]);
      if(addr)
        fprintf(fp, "    %s = 0x%lx\n", dsyms[s], (unsigned long)addr);
    }

    /* Dump first 256 bytes of dipsw library code */
    if(dipsw_base) {
      unsigned char code[256];
      if(!kernel_proc_copyout(pid, dipsw_base, code, 256)) {
        fprintf(fp, "\n  libSceDipsw code dump (first 256 bytes):\n");
        for(int i = 0; i < 256; i += 16) {
          fprintf(fp, "    0x%lx: ", (unsigned long)(dipsw_base + i));
          for(int j = 0; j < 16; j++)
            fprintf(fp, "%02x ", code[i+j]);
          fprintf(fp, "\n");
        }
      }
    }
  }

  /* Scan eboot for devkit panel strings */
  size_t chunk_sz = 256 * 1024;
  unsigned char *buf = malloc(chunk_sz);
  if(!buf) return;

  const char *needles[] = {
    "QSP_set_host_system_info",
    "QSP_get_device_ip_address",
    "QSP_get_device_key_label",
    "devkit_panel",
    "DevKitPanel",
    "devkitpanel",
    "host_overlay",
    "overlayPosition",
    "GetGlsOverlayPosition",
    "SetGlsOverlayPosition",
    "GnmCompositorOnScreenProfiler",
    "DevKit/TestKit",
    "rnps-notification-overlay",
    "check_genuine_devkit",
    "MinimumDebugMenu",
    NULL
  };

  fprintf(fp, "\n  Scanning SceShellUI eboot for devkit-panel strings...\n");
  int total_hits = 0;

  for(size_t off = 0; off < 16UL * 1024 * 1024; off += chunk_sz) {
    if(kernel_proc_copyout(pid, base + off, buf, chunk_sz))
      break;

    int all_zero = 1;
    for(size_t c = 0; c < 256; c++) {
      if(buf[c]) { all_zero = 0; break; }
    }
    if(all_zero) break;

    for(int n = 0; needles[n]; n++) {
      size_t nlen = strlen(needles[n]);
      for(size_t j = 0; j + nlen <= chunk_sz; j++) {
        if(!memcmp(&buf[j], needles[n], nlen)) {
          fprintf(fp, "    \"%s\" at 0x%lx\n",
                  needles[n], (unsigned long)(base + off + j));
          total_hits++;
        }
      }
    }
  }

  fprintf(fp, "  Total hits: %d\n", total_hits);
  free(buf);
}

/* Phase 6: Check some registry keys that might relate to devkit panel */
static void
check_registry_keys(FILE *fp) {
  fprintf(fp, "\n=== REGISTRY CHECK ===\n\n");

  struct { unsigned int id; const char *name; } keys[] = {
    { 0x7802A400, "DEVENV_TOOL_host_overlay" },
    { 0x7802A900, "DEVENV_TOOL_shell_debug" },
    { 0x7802C901, "DEVENV_TOOL_SHELLUI_debug_menu" },
    { 0x7802C9C8, "DEVENV_TOOL_SHELLUI_content_info" },
    { 0x02000000, "SYSTEM_0" },
    { 0x02000001, "SYSTEM_1" },
    { 0x02800400, "SYSTEM_UPDATE_MODE" },
    { 0, NULL }
  };

  for(int i = 0; keys[i].name; i++) {
    int val = 0;
    int err = sceRegMgrGetInt(keys[i].id, &val);
    if(!err)
      fprintf(fp, "  0x%08x (%s) = %d (0x%x)\n",
              keys[i].id, keys[i].name, val, val);
    else
      fprintf(fp, "  0x%08x (%s) = err 0x%08x\n",
              keys[i].id, keys[i].name, err);
  }

  /* Try setting host_overlay to 1 */
  fprintf(fp, "\n  Trying to set DEVENV_TOOL_host_overlay = 1...\n");
  int serr = sceRegMgrSetInt(0x7802A400, 1);
  fprintf(fp, "  sceRegMgrSetInt(0x7802A400, 1) = 0x%08x\n", serr);

  /* Try setting shell_debug to 1 */
  fprintf(fp, "  Trying to set DEVENV_TOOL_shell_debug = 1...\n");
  serr = sceRegMgrSetInt(0x7802A900, 1);
  fprintf(fp, "  sceRegMgrSetInt(0x7802A900, 1) = 0x%08x\n", serr);
}

int
main(void) {
  mkdir(OUT_DIR, 0777);
  elevate();
  notify("dipswpatch: starting...");
  printf("dipswpatch: elevated\n");

  char path[256];
  snprintf(path, sizeof(path), "%s/dipswpatch.txt", OUT_DIR);
  FILE *fp = fopen(path, "w");
  if(!fp) { perror(path); return 1; }

  fprintf(fp, "=== PRE-PATCH STATE ===\n");
  fprintf(fp, "  sceKernelIsDevKit()  = %d\n", sceKernelIsDevKit());
  fprintf(fp, "  sceKernelIsTestKit() = %d\n", sceKernelIsTestKit());
  fprintf(fp, "  sceKernelIsCEX()     = %d\n", sceKernelIsCEX());
  fprintf(fp, "  SECURITY_FLAGS = 0x%02x\n",
          kernel_getchar(KERNEL_ADDRESS_SECURITY_FLAGS));
  fprintf(fp, "  TARGETID = 0x%02x\n",
          kernel_getchar(KERNEL_ADDRESS_TARGETID));
  fprintf(fp, "\n");

  /* Phase 1: Read DIP switches */
  read_dipsw(fp);

  /* Phase 2: Dump kernel flags area (safe, small reads only) */
  dump_kernel_flags(fp);

  /* Phase 3: Patch process stubs */
  pid_t shellui_pid = find_process("SceShellUI");
  pid_t shellcore_pid = find_process("SceShellCore");

  int patched_ui = 0, patched_core = 0;
  if(shellui_pid > 0)
    patched_ui = patch_process_stubs(fp, shellui_pid, "SceShellUI");
  if(shellcore_pid > 0)
    patched_core = patch_process_stubs(fp, shellcore_pid, "SceShellCore");

  /* Phase 4: Compositor profiler */
  try_compositor_profiler(fp);

  /* Phase 5: Scan ShellUI for devkit panel strings */
  scan_shellui_devkit_strings(fp);

  /* Phase 6: Registry keys */
  check_registry_keys(fp);

  /* Post-patch state from OUR process */
  fprintf(fp, "\n=== POST-PATCH STATE (from payload process) ===\n");
  fprintf(fp, "  sceKernelIsDevKit()  = %d\n", sceKernelIsDevKit());
  fprintf(fp, "  sceKernelIsTestKit() = %d\n", sceKernelIsTestKit());
  fprintf(fp, "  sceKernelIsCEX()     = %d\n", sceKernelIsCEX());
  fprintf(fp, "\n  Patched SceShellUI stubs: %d\n", patched_ui);
  fprintf(fp, "  Patched SceShellCore stubs: %d\n", patched_core);

  fprintf(fp, "\n=== NOTES ===\n");
  fprintf(fp, "Patches are to userspace libkernel stubs. They affect\n");
  fprintf(fp, "the target processes only, and are lost on restart.\n");
  fprintf(fp, "SceShellUI may need restart (killshell) to re-evaluate.\n");
  fprintf(fp, "BUT: it will get fresh unpatched stubs on restart.\n");
  fprintf(fp, "For persistence, the kernel syscall handler must be patched.\n");

  fclose(fp);
  printf("dipswpatch: wrote %s\n", path);
  notify("dipswpatch: done - check results");
  printf("dipswpatch: done\n");
  return 0;
}
