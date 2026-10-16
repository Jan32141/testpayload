/* Deep scan for devkit panel: walk kernel proc list, read SceShellUI memory,
 * scan decrypted modules in-memory, check DIP switches and kernel flags.
 * Uses kernel_proc_copyout to bypass ptrace and sysctl limitations. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>

#include <ps5/kernel.h>

#define OUT_DIR "/data/testpayload"

/* SCE syscalls */
int sceKernelGetProcessName(pid_t, char *);
int sceKernelIsDevKit(void);
int sceKernelIsTestKit(void);
int sceKernelIsGenuineDevKit(void);
int sceKernelIsGenuineTestKit(void);
int sceKernelIsCEX(void);
int sceKernelGetGPI(unsigned int *);
int sceKernelGetGPO(unsigned int *);
int sceKernelGetSafemode(unsigned int *);
int sceKernelGetBasicProductShape(unsigned int *);

int sceRegMgrGetInt(unsigned int regId, int *value);
int sceRegMgrGetStr(unsigned int regId, char *buf, size_t size);
int sceRegMgrGetBin(unsigned int regId, void *buf, size_t size);

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

static const char *needles[] = {
  "devkit", "DevKit", "DEVKIT",
  "devpanel", "DevPanel", "devPanel",
  "dev_panel", "dev-panel",
  "overlay", "Overlay", "host_overlay",
  "debug_menu", "DebugMenu",
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
  "host_name", "HostName",
  "sceRegMgr",
  "0x78020000", "0x7802",
  "BGLayer", "bgLayer",
  "StatusBar", "statusBar", "status_bar",
  "InfoBar", "infoBar", "info_bar",
  "ToolBar", "toolBar", "tool_bar",
  "HUD", "hud_overlay",
  "SystemInfo", "system_info",
  "DevInfo", "dev_info",
  "FPS", "fps_counter",
  "TargetInfo", "target_info",
  "IPAddress", "ip_address",
  "FirmwareVersion", "firmware_version",
  "BuildInfo", "build_info",
  "DipSwitch", "dipsw", "DIPSW",
  "isDevKit", "isTestKit",
  "product_mode", "ProductMode",
  "manu_mode", "ManuMode",
  NULL
};

static int
search_in_data(FILE *fp, const unsigned char *data, size_t len,
               const char *source, size_t base_offset, int max_hits) {
  int total_hits = 0;
  for(int n = 0; needles[n] && total_hits < max_hits; n++) {
    size_t nlen = strlen(needles[n]);
    for(size_t i = 0; i + nlen <= len && total_hits < max_hits; i++) {
      if(!memcmp(&data[i], needles[n], nlen)) {
        fprintf(fp, "  MATCH \"%s\" in %s at offset 0x%zx\n",
                needles[n], source, base_offset + i);
        size_t ctx_start = (i >= 32) ? i - 32 : 0;
        size_t ctx_len = 96;
        if(ctx_start + ctx_len > len) ctx_len = len - ctx_start;
        hexdump_fp(fp, &data[ctx_start], ctx_len, base_offset + ctx_start);
        total_hits++;
      }
    }
  }
  return total_hits;
}

/* Phase 1: Enumerate all processes by iterating PIDs via kernel */
static pid_t
find_all_procs(FILE *fp) {
  fprintf(fp, "--- PROCESS LIST (kernel walk) ---\n");
  pid_t shell_pid = -1;
  int count = 0;

  for(pid_t p = 0; p < 2000; p++) {
    intptr_t proc_addr = kernel_get_proc(p);
    if(!proc_addr) continue;

    char name[64] = {0};
    int err = sceKernelGetProcessName(p, name);
    if(err) {
      /* fallback: read p_comm from proc struct directly
       * on FreeBSD/PS5, p_comm is typically at offset ~0x59C in struct proc */
      kernel_copyout(proc_addr + 0x59c, name, 32);
      name[31] = 0;
    }

    fprintf(fp, "  PID %5d  proc=0x%lx  %s\n", p, (unsigned long)proc_addr, name);
    printf("deepscan: PID %d = %s\n", p, name);
    count++;

    if(strstr(name, "SceShellUI") || strstr(name, "ShellUI") ||
       strstr(name, "shellui"))
      shell_pid = p;
  }
  fprintf(fp, "  total: %d processes\n\n", count);
  return shell_pid;
}

/* Phase 2: Walk allproc linked list directly */
static pid_t
walk_allproc(FILE *fp) {
  fprintf(fp, "--- ALLPROC LINKED LIST WALK ---\n");
  fprintf(fp, "  ALLPROC @ 0x%lx\n", (unsigned long)KERNEL_ADDRESS_ALLPROC);

  if(!KERNEL_ADDRESS_ALLPROC) {
    fprintf(fp, "  ALLPROC not available\n\n");
    return -1;
  }

  pid_t shell_pid = -1;
  intptr_t proc_ptr = 0;
  kernel_copyout(KERNEL_ADDRESS_ALLPROC, &proc_ptr, sizeof(proc_ptr));
  fprintf(fp, "  first proc: 0x%lx\n", (unsigned long)proc_ptr);

  int count = 0;
  while(proc_ptr && count < 500) {
    int32_t pid = 0;
    kernel_copyout(proc_ptr + KERNEL_OFFSET_PROC_P_PID, &pid, sizeof(pid));

    char comm[32] = {0};
    /* p_comm offset: try standard FreeBSD offset */
    kernel_copyout(proc_ptr + 0x59c, comm, sizeof(comm) - 1);

    fprintf(fp, "  [%3d] PID %5d  proc=0x%lx  %s\n",
            count, pid, (unsigned long)proc_ptr, comm);

    if(strstr(comm, "SceShell") || strstr(comm, "shell"))
      shell_pid = pid;

    /* follow p_list.le_next (first field of struct proc) */
    intptr_t next = 0;
    kernel_copyout(proc_ptr, &next, sizeof(next));
    proc_ptr = next;
    count++;
  }
  fprintf(fp, "  walked %d entries\n\n", count);
  return shell_pid;
}

/* Phase 3: Enumerate loaded modules in a process */
static void
scan_proc_modules(FILE *fp, pid_t pid) {
  fprintf(fp, "--- LOADED MODULES for PID %d ---\n", pid);

  /* Try common library names that SceShellUI would have loaded */
  const char *libs[] = {
    "libkernel.sprx",
    "libkernel_sys.sprx",
    "libSceLibcInternal.sprx",
    "libSceSysmodule.sprx",
    "libSceRegMgr.sprx",
    "libSceSystemService.sprx",
    "libSceShellCoreUtil.sprx",
    "libSceDipsw.sprx",
    "libSceNet.sprx",
    "libSceIpmi.sprx",
    "libSceIdu.sprx",
    "libSceCompositorClient.sprx",
    "libSceNpManager.sprx",
    "libScePad.sprx",
    "SceShellUI.self",
    "eboot.bin",
    NULL
  };

  for(int i = 0; libs[i]; i++) {
    uint32_t handle = 0;
    int err = kernel_dynlib_handle(pid, libs[i], &handle);
    if(err) continue;

    intptr_t base = kernel_dynlib_mapbase_addr(pid, handle);
    intptr_t entry = kernel_dynlib_entry_addr(pid, handle);

    fprintf(fp, "  %-40s handle=0x%x  base=0x%lx  entry=0x%lx\n",
            libs[i], handle, (unsigned long)base, (unsigned long)entry);
    printf("deepscan: found module %s at 0x%lx in PID %d\n",
           libs[i], (unsigned long)base, pid);
  }
  fprintf(fp, "\n");
}

/* Phase 4: Scan process memory for strings */
static void
scan_proc_memory(FILE *fp, pid_t pid) {
  fprintf(fp, "--- PROCESS MEMORY SCAN for PID %d ---\n", pid);
  printf("deepscan: scanning PID %d memory...\n", pid);

  /* Try common library names and scan their memory regions */
  const char *scan_libs[] = {
    "libSceShellCoreUtil.sprx",
    "libSceRegMgr.sprx",
    "libSceDipsw.sprx",
    "libSceCompositorClient.sprx",
    "libSceSystemService.sprx",
    "eboot.bin",
    NULL
  };

  int total_hits = 0;

  for(int i = 0; scan_libs[i]; i++) {
    uint32_t handle = 0;
    if(kernel_dynlib_handle(pid, scan_libs[i], &handle))
      continue;

    intptr_t base = kernel_dynlib_mapbase_addr(pid, handle);
    if(!base) continue;

    /* scan chunks of the loaded module */
    size_t chunk = 256 * 1024;
    unsigned char *buf = malloc(chunk);
    if(!buf) continue;

    for(size_t off = 0; off < 16 * 1024 * 1024; off += chunk) {
      memset(buf, 0, chunk);
      int err = kernel_proc_copyout(pid, base + off, buf, chunk);
      if(err) break;

      /* check if the region is all zeros (unmapped) */
      int all_zero = 1;
      for(size_t c = 0; c < 256; c++) {
        if(buf[c]) { all_zero = 0; break; }
      }
      if(all_zero) break;

      char label[256];
      snprintf(label, sizeof(label), "%s+0x%zx[PID %d]", scan_libs[i], off, pid);
      int hits = search_in_data(fp, buf, chunk, label, base + off, 200);
      total_hits += hits;
      if(hits)
        printf("deepscan: %d hits in %s+0x%zx\n", hits, scan_libs[i], off);
    }
    free(buf);
  }

  /* Also do a broad scan: try reading the process's first ~64MB in 1MB chunks */
  fprintf(fp, "\n  --- Broad memory scan ---\n");
  size_t chunk = 1024 * 1024;
  unsigned char *buf = malloc(chunk);
  if(buf) {
    /* Common PS5 process base addresses to try */
    intptr_t bases[] = {
      0x400000,      /* typical ELF base */
      0x800000000,   /* common module load area */
      0x880000000,
      0x900000000,
      0
    };

    for(int b = 0; bases[b]; b++) {
      int consecutive_fails = 0;
      for(size_t off = 0; off < 64 * 1024 * 1024 && consecutive_fails < 3; off += chunk) {
        memset(buf, 0, chunk);
        int err = kernel_proc_copyout(pid, bases[b] + off, buf, chunk);
        if(err) { consecutive_fails++; continue; }
        consecutive_fails = 0;

        int all_zero = 1;
        for(size_t c = 0; c < 256; c++) {
          if(buf[c]) { all_zero = 0; break; }
        }
        if(all_zero) continue;

        char label[256];
        snprintf(label, sizeof(label), "mem[0x%lx+0x%zx]",
                 (unsigned long)bases[b], off);
        int hits = search_in_data(fp, buf, chunk, label, bases[b] + off, 200);
        total_hits += hits;
        if(hits)
          printf("deepscan: %d hits at 0x%lx+0x%zx\n",
                 hits, (unsigned long)bases[b], off);
      }
    }
    free(buf);
  }
  fprintf(fp, "  total hits: %d\n\n", total_hits);
}

/* Phase 5: Check DIP switch flags and kernel detection APIs */
static void
check_system_flags(FILE *fp) {
  fprintf(fp, "--- SYSTEM FLAGS & DIP SWITCHES ---\n");

  int val;
  val = sceKernelIsDevKit();
  fprintf(fp, "  sceKernelIsDevKit()          = %d\n", val);
  val = sceKernelIsTestKit();
  fprintf(fp, "  sceKernelIsTestKit()         = %d\n", val);
  val = sceKernelIsGenuineDevKit();
  fprintf(fp, "  sceKernelIsGenuineDevKit()   = %d\n", val);
  val = sceKernelIsGenuineTestKit();
  fprintf(fp, "  sceKernelIsGenuineTestKit()  = %d\n", val);
  val = sceKernelIsCEX();
  fprintf(fp, "  sceKernelIsCEX()             = %d\n", val);

  unsigned int gpi = 0, gpo = 0;
  sceKernelGetGPI(&gpi);
  sceKernelGetGPO(&gpo);
  fprintf(fp, "  GPI = 0x%08x  GPO = 0x%08x\n", gpi, gpo);

  unsigned int safemode = 0;
  sceKernelGetSafemode(&safemode);
  fprintf(fp, "  safemode = %u\n", safemode);

  unsigned int shape = 0;
  sceKernelGetBasicProductShape(&shape);
  fprintf(fp, "  product_shape = %u\n", shape);

  /* Read kernel flags */
  uint8_t sf = kernel_getchar(KERNEL_ADDRESS_SECURITY_FLAGS);
  uint8_t tid = kernel_getchar(KERNEL_ADDRESS_TARGETID);
  fprintf(fp, "  SECURITY_FLAGS = 0x%02x\n", sf);
  fprintf(fp, "    DEBUG_SETTING_MODE  = %d\n", !!(sf & 0x01));
  fprintf(fp, "    ALLOW_UNSIGNED_CODE = %d\n", !!(sf & 0x04));
  fprintf(fp, "    DEVKIT_MODE         = %d\n", !!(sf & 0x80));
  fprintf(fp, "  TARGETID = 0x%02x\n", tid);

  uint8_t qa[16] = {0};
  kernel_copyout(KERNEL_ADDRESS_QA_FLAGS, qa, sizeof(qa));
  fprintf(fp, "  QA_FLAGS = ");
  for(int i = 0; i < 16; i++) fprintf(fp, "%02x", qa[i]);
  fprintf(fp, "\n");
  fprintf(fp, "    QA_ENABLED                = %d\n", !!(qa[0] & 0x02));
  fprintf(fp, "    ALLOW_DEBUG_MENU          = %d\n", !!(qa[0] & 0x04));
  fprintf(fp, "    ENABLE_TESTKIT_FEATURES   = %d\n", !!(qa[2] & 0x01));

  uint8_t ut[16] = {0};
  kernel_copyout(KERNEL_ADDRESS_UTOKEN_FLAGS, ut, sizeof(ut));
  fprintf(fp, "  UTOKEN_FLAGS = ");
  for(int i = 0; i < 16; i++) fprintf(fp, "%02x", ut[i]);
  fprintf(fp, "\n");

  fprintf(fp, "\n");
}

/* Phase 6: Try resolving specific symbols in SceShellCore / SceShellUI */
static void
try_resolve_symbols(FILE *fp, pid_t pid) {
  fprintf(fp, "--- SYMBOL RESOLUTION in PID %d ---\n", pid);

  /* Try to find SceShellCore symbols related to devkit panel */
  const char *try_libs[] = {
    "libSceShellCoreUtil.sprx",
    "libSceSystemService.sprx",
    "libSceDipsw.sprx",
    "libSceRegMgr.sprx",
    NULL
  };

  const char *try_syms[] = {
    "sceShellCoreUtilGetDevKitPanel",
    "sceShellCoreUtilSetDevKitPanel",
    "sceShellCoreUtilIsDevKit",
    "sceShellCoreUtilGetOverlay",
    "sceShellCoreUtilSetOverlay",
    "sceShellCoreUtilGetDebugMenu",
    "sceShellCoreUtilGetDevPanel",
    "sceShellCoreUtilSetDevPanel",
    "sceSystemServiceGetDevKitPanel",
    "sceSystemServiceSetDevKitPanel",
    "sceSystemServiceGetDevPanel",
    "sceSystemServiceSetDevPanel",
    "sceDipswIsDevKit",
    "sceDipswIsTestKit",
    "sceDipswGetFlag",
    "sceDipswSetFlag",
    "sceDipswGetValue",
    "sceDipswSetValue",
    "sceDipswGetInfo",
    "sceDipswIsDevelopmentMode",
    NULL
  };

  for(int l = 0; try_libs[l]; l++) {
    uint32_t handle = 0;
    if(kernel_dynlib_handle(pid, try_libs[l], &handle))
      continue;

    fprintf(fp, "  [%s] handle=0x%x\n", try_libs[l], handle);

    for(int s = 0; try_syms[s]; s++) {
      intptr_t addr = kernel_dynlib_dlsym(pid, handle, try_syms[s]);
      if(addr) {
        fprintf(fp, "    FOUND: %s @ 0x%lx\n", try_syms[s], (unsigned long)addr);
        printf("deepscan: FOUND symbol %s at 0x%lx\n", try_syms[s], (unsigned long)addr);
      }
    }
  }
  fprintf(fp, "\n");
}

/* Phase 7: Scan non-encrypted ELF files on disk */
static void
scan_elf_file(FILE *fp, const char *path) {
  int fd = open(path, O_RDONLY);
  if(fd < 0) {
    fprintf(fp, "  cannot open %s\n", path);
    return;
  }

  struct stat st;
  fstat(fd, &st);
  fprintf(fp, "  %s (%ld bytes)\n", path, (long)st.st_size);

  if(st.st_size > 50 * 1024 * 1024) {
    fprintf(fp, "    too large, skipping\n");
    close(fd);
    return;
  }

  unsigned char *data = malloc(st.st_size);
  if(!data) { close(fd); return; }

  ssize_t total = 0;
  while(total < st.st_size) {
    ssize_t n = read(fd, data + total, st.st_size - total);
    if(n <= 0) break;
    total += n;
  }
  close(fd);

  /* Check ELF magic */
  if(total >= 4 && data[0] == 0x7f && data[1] == 'E' &&
     data[2] == 'L' && data[3] == 'F') {
    fprintf(fp, "    valid ELF header, scanning...\n");
  } else if(total >= 4 && data[0] == 0x4f && data[1] == 0x15 &&
            data[2] == 0x3d && data[3] == 0x1d) {
    fprintf(fp, "    SCE encrypted SELF header (0x4f153d1d), skipping\n");
    free(data);
    return;
  } else {
    fprintf(fp, "    magic: %02x %02x %02x %02x, scanning anyway...\n",
            total > 0 ? data[0] : 0, total > 1 ? data[1] : 0,
            total > 2 ? data[2] : 0, total > 3 ? data[3] : 0);
  }

  int hits = search_in_data(fp, data, total, path, 0, 500);
  fprintf(fp, "    %d hits\n", hits);
  if(hits)
    printf("deepscan: %d hits in %s\n", hits, path);

  free(data);
}

/* Phase 8: Check additional registry keys that might control the panel */
static void
check_extra_registry(FILE *fp) {
  fprintf(fp, "--- ADDITIONAL REGISTRY KEYS ---\n");

  struct { unsigned int key; const char *name; } int_keys[] = {
    { 0x7802C9C8, "DEVENV_TOOL_SHELLUI_content_info" },
    { 0x7802C901, "DEVENV_TOOL_SHELLUI_debug_menu" },
    { 0x7802C9C6, "DEVENV_TOOL_SHELLUI_disp_titleid" },
    { 0x7802A400, "DEVENV_TOOL_host_overlay" },
    { 0x7802A900, "DEVENV_TOOL_shell_debug" },
    { 0x7802AD00, "DEVENV_TOOL_compositor_dbg" },
    { 0x02860200, "SYSTEM_SPECIFIC_show_mode" },
    { 0x02820100, "SYSTEM_0x02820100" },
    { 0x02820500, "SYSTEM_0x02820500" },
    { 0x02820600, "SYSTEM_0x02820600" },
    { 0x02820800, "SYSTEM_0x02820800" },
    { 0x02820F00, "SYSTEM_0x02820F00" },
    { 0x02880200, "SYSTEM_0x02880200" },
    { 0x02880300, "SYSTEM_0x02880300" },
    /* try DipSw-related ranges */
    { 0x3C000000, "DIPSW_0x3C000000" },
    { 0x3C000100, "DIPSW_0x3C000100" },
    { 0x3C010000, "DIPSW_0x3C010000" },
    { 0x3C020000, "DIPSW_0x3C020000" },
    /* system update/debug */
    { 0x02010000, "SYSTEM_UPDATE_0x02010000" },
    { 0x02010100, "SYSTEM_UPDATE_0x02010100" },
    /* accessibility / UI */
    { 0x09010000, "ACCESSIBILITY_0x09010000" },
    { 0x09010100, "ACCESSIBILITY_0x09010100" },
    { 0x09020000, "ACCESSIBILITY_0x09020000" },
    { 0 , NULL }
  };

  for(int i = 0; int_keys[i].name; i++) {
    int val = 0;
    int err = sceRegMgrGetInt(int_keys[i].key, &val);
    if(!err) {
      fprintf(fp, "  INT 0x%08x %-40s = %d (0x%x)\n",
              int_keys[i].key, int_keys[i].name, val, val);
    } else if(err != (int)0x800d0203) {
      fprintf(fp, "  INT 0x%08x %-40s err=0x%08x\n",
              int_keys[i].key, int_keys[i].name, err);
    }
  }

  /* try string reads on keys that returned 0x800d0218 (type mismatch) */
  struct { unsigned int key; const char *name; } str_keys[] = {
    { 0x02800200, "SYSTEM_0x02800200" },
    { 0x02800300, "SYSTEM_0x02800300" },
    { 0x02804000, "SYSTEM_0x02804000" },
    { 0x02820200, "SYSTEM_0x02820200" },
    { 0x02820300, "SYSTEM_0x02820300" },
    { 0x02820400, "SYSTEM_0x02820400" },
    { 0x02820700, "SYSTEM_0x02820700" },
    { 0x02860100, "SYSTEM_0x02860100" },
    { 0x02860300, "SYSTEM_0x02860300" },
    { 0x02860500, "SYSTEM_0x02860500" },
    { 0x02880100, "SYSTEM_0x02880100" },
    { 0 , NULL }
  };

  fprintf(fp, "\n  --- String reads for type-mismatch keys ---\n");
  for(int i = 0; str_keys[i].name; i++) {
    char buf[512] = {0};
    int err = sceRegMgrGetStr(str_keys[i].key, buf, sizeof(buf));
    if(!err && buf[0]) {
      fprintf(fp, "  STR 0x%08x %-30s = \"%s\"\n",
              str_keys[i].key, str_keys[i].name, buf);
    } else if(!err) {
      fprintf(fp, "  STR 0x%08x %-30s = (empty)\n",
              str_keys[i].key, str_keys[i].name);
    } else if(err != (int)0x800d0203 && err != (int)0x800d0218) {
      fprintf(fp, "  STR 0x%08x %-30s err=0x%08x\n",
              str_keys[i].key, str_keys[i].name, err);
    }

    /* also try binary read */
    unsigned char binbuf[64] = {0};
    err = sceRegMgrGetBin(str_keys[i].key, binbuf, sizeof(binbuf));
    if(!err) {
      fprintf(fp, "  BIN 0x%08x %-30s = ", str_keys[i].key, str_keys[i].name);
      for(int j = 0; j < 32; j++) fprintf(fp, "%02x", binbuf[j]);
      fprintf(fp, "\n");
    }
  }
  fprintf(fp, "\n");
}

int
main(void) {
  mkdir(OUT_DIR, 0777);
  elevate();
  printf("deepscan: elevated\n");
  notify("deepscan: starting deep shell scan");

  FILE *fp;
  char path[256];
  snprintf(path, sizeof(path), "%s/deepscan.txt", OUT_DIR);
  fp = fopen(path, "w");
  if(!fp) { perror(path); return 1; }

  fprintf(fp, "=== DEEP DEVKIT PANEL SCAN ===\n\n");

  /* Phase 1: System flags */
  check_system_flags(fp);
  fflush(fp);

  /* Phase 2: Find processes */
  pid_t shell_pid = find_all_procs(fp);
  fflush(fp);

  /* Phase 3: Walk allproc as backup */
  pid_t shell_pid2 = walk_allproc(fp);
  if(shell_pid < 0) shell_pid = shell_pid2;
  fprintf(fp, "SceShellUI PID: %d\n\n", shell_pid);
  printf("deepscan: SceShellUI PID=%d\n", shell_pid);
  fflush(fp);

  /* Phase 4: If we found SceShellUI, enumerate its modules and scan memory */
  if(shell_pid > 0) {
    scan_proc_modules(fp, shell_pid);
    fflush(fp);
    try_resolve_symbols(fp, shell_pid);
    fflush(fp);
    scan_proc_memory(fp, shell_pid);
    fflush(fp);
  } else {
    fprintf(fp, "SceShellUI not found, trying SceShellCore...\n");
    /* Try other shell processes */
    for(pid_t p = 1; p < 100; p++) {
      intptr_t pa = kernel_get_proc(p);
      if(!pa) continue;
      char name[64] = {0};
      sceKernelGetProcessName(p, name);
      if(strstr(name, "Sce") || strstr(name, "sce")) {
        fprintf(fp, "  trying PID %d (%s)...\n", p, name);
        scan_proc_modules(fp, p);
        try_resolve_symbols(fp, p);
      }
    }
    fflush(fp);
  }

  /* Phase 5: Scan files on disk */
  fprintf(fp, "--- ON-DISK BINARY SCAN ---\n");
  const char *elf_files[] = {
    "/system/vsh/SceShellCore.elf",
    "/system_ex/app/NPXS40087/eboot.bin",
    "/system/common/lib/libSceRegMgr.sprx",
    "/system/priv/lib/libSceDipsw.sprx",
    "/system/common/lib/libSceSystemService.sprx",
    "/system_ex/common_ex/lib/Sce.Vsh.ShellUI.BGLayer.dll.sprx",
    "/system_ex/common_ex/lib/Sce.Vsh.ShellUI.BaseSystem.dll.sprx",
    "/system_ex/common_ex/lib/Sce.Vsh.Registry.dll.sprx",
    NULL
  };
  for(int i = 0; elf_files[i]; i++) {
    printf("deepscan: scanning %s...\n", elf_files[i]);
    scan_elf_file(fp, elf_files[i]);
  }
  fprintf(fp, "\n");
  fflush(fp);

  /* Phase 6: Extra registry keys */
  check_extra_registry(fp);
  fflush(fp);

  fclose(fp);
  printf("deepscan: wrote %s\n", path);
  printf("deepscan: done\n");
  notify("deepscan: complete - check /data/testpayload/deepscan.txt");
  return 0;
}
