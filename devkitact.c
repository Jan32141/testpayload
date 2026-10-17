/* devkitact: Activate devkit panel via dipsw + sysctl patching.
 * 1. Read all dipsw values using correct ioctl (0xC0088803)
 * 2. Try setting devkit-related dipsw flags (0x80028801)
 * 3. Find and patch machdep.check_genuine_devkit_for_psm in kernel
 * 4. Patch sceKernelIsDevKit stubs if needed
 *
 * SAFETY: NEVER touches IDU mode. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <errno.h>

#include <ps5/kernel.h>

#define OUT_DIR "/data/testpayload"

int sceKernelGetProcessName(pid_t, char *);
int sceKernelIsDevKit(void);
int sceKernelIsTestKit(void);
int sceKernelIsCEX(void);

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

/* DIP switch ioctl commands - decoded from libSceDipsw.sprx binary.
 * Group = 0x88 (not 'd'=0x64 as we assumed earlier).
 * Buffer for read is 8 bytes: {uint16 index, uint16 pad, uint32 value} */
#define DIPSW_IOCTL_INIT     0x20008800
#define DIPSW_IOCTL_SET      0x80028801  /* set flag by index (2 bytes) */
#define DIPSW_IOCTL_CLEAR    0x80028802  /* clear flag by index (2 bytes) */
#define DIPSW_IOCTL_READ     0xC0088803  /* read value (8 bytes in/out) */
#define DIPSW_IOCTL_WRITE4   0x80108804  /* write 16 bytes */
#define DIPSW_IOCTL_WRITE5   0x80108805  /* write 16 bytes */
#define DIPSW_IOCTL_CONFIG   0x8010880a  /* read/write config (16 bytes) */

struct dipsw_read_req {
  uint16_t index;
  uint16_t pad;
  uint32_t value;
};

/* Phase 1: Read all DIP switches with correct ioctl */
static void
read_all_dipsw(FILE *fp) {
  fprintf(fp, "=== DIP SWITCH DUMP (correct ioctl 0xC0088803) ===\n\n");

  int fd = open("/dev/dipsw", O_RDWR);
  if(fd < 0) {
    fd = open("/dev/dipsw", O_RDONLY);
  }
  if(fd < 0) {
    fprintf(fp, "  Cannot open /dev/dipsw: %d\n", errno);
    return;
  }
  fprintf(fp, "  /dev/dipsw fd=%d\n\n", fd);

  /* Try init ioctl first */
  int init_ret = ioctl(fd, DIPSW_IOCTL_INIT, 0);
  fprintf(fp, "  Init ioctl (0x20008800): %d (errno=%d)\n\n", init_ret, errno);

  /* Read all 256 dipsw indices */
  int nonzero_count = 0;
  fprintf(fp, "  Reading all 256 dipsw values:\n");
  for(int idx = 0; idx < 256; idx++) {
    struct dipsw_read_req req;
    memset(&req, 0, sizeof(req));
    req.index = (uint16_t)idx;

    int ret = ioctl(fd, DIPSW_IOCTL_READ, &req);
    if(ret == 0) {
      if(req.value != 0 || idx < 32) {
        fprintf(fp, "    dipsw[0x%02x] = 0x%08x (%u)\n",
                idx, req.value, req.value);
      }
      if(req.value != 0) nonzero_count++;
    } else if(idx < 32) {
      fprintf(fp, "    dipsw[0x%02x] = read error %d (errno=%d)\n",
              idx, ret, errno);
    }
  }
  fprintf(fp, "\n  Total non-zero: %d\n", nonzero_count);

  /* Also try the config ioctl */
  fprintf(fp, "\n  Config ioctl (0x8010880a):\n");
  unsigned char config[16];
  memset(config, 0, sizeof(config));
  int cfg_ret = ioctl(fd, DIPSW_IOCTL_CONFIG, config);
  fprintf(fp, "    ret=%d: ", cfg_ret);
  for(int i = 0; i < 16; i++) fprintf(fp, "%02x ", config[i]);
  fprintf(fp, "\n");

  close(fd);
}

/* Phase 2: Try to set devkit-related dipsw flags.
 * From the wrapper functions in libSceDipsw:
 *   func(0)    - dipsw[0]   general system type?
 *   func(2)    - dipsw[2]   devkit/testkit flag?
 *   func(0x18) - dipsw[24]  ?
 *   func(0x1e) - dipsw[30]  ?
 *
 * IMPORTANT: These are hardware DIP switches. Setting them
 * might change fundamental system behavior. We only set flags
 * that appear related to devkit mode, after reading current state. */
static void
try_set_dipsw_flags(FILE *fp) {
  fprintf(fp, "\n=== DIP SWITCH FLAG SETTING ===\n\n");

  int fd = open("/dev/dipsw", O_RDWR);
  if(fd < 0) {
    fprintf(fp, "  Cannot open /dev/dipsw for writing\n");
    return;
  }

  /* First read current values for the interesting indices */
  int indices[] = { 0, 1, 2, 3, 0x18, 0x1e, -1 };
  for(int i = 0; indices[i] >= 0; i++) {
    struct dipsw_read_req req = { .index = indices[i], .pad = 0, .value = 0 };
    ioctl(fd, DIPSW_IOCTL_READ, &req);
    fprintf(fp, "  Before: dipsw[0x%02x] = 0x%08x\n", indices[i], req.value);
  }

  /* Try setting dipsw[2] - this is what sceDipswIsDevKit likely checks
   * (the wrapper func(2) reads dipsw[2]) */
  fprintf(fp, "\n  Setting dipsw[2] (devkit flag)...\n");
  uint16_t set_idx = 2;
  int ret = ioctl(fd, DIPSW_IOCTL_SET, &set_idx);
  fprintf(fp, "    ioctl SET dipsw[2]: ret=%d errno=%d\n", ret, errno);

  /* Read back */
  struct dipsw_read_req req2 = { .index = 2, .pad = 0, .value = 0 };
  ioctl(fd, DIPSW_IOCTL_READ, &req2);
  fprintf(fp, "    After SET: dipsw[2] = 0x%08x\n", req2.value);

  /* Also try index 0 */
  fprintf(fp, "\n  Setting dipsw[0]...\n");
  set_idx = 0;
  ret = ioctl(fd, DIPSW_IOCTL_SET, &set_idx);
  fprintf(fp, "    ioctl SET dipsw[0]: ret=%d errno=%d\n", ret, errno);

  struct dipsw_read_req req0 = { .index = 0, .pad = 0, .value = 0 };
  ioctl(fd, DIPSW_IOCTL_READ, &req0);
  fprintf(fp, "    After SET: dipsw[0] = 0x%08x\n", req0.value);

  /* Check if sceKernelIsDevKit changed */
  fprintf(fp, "\n  After dipsw changes:\n");
  fprintf(fp, "    sceKernelIsDevKit()  = %d\n", sceKernelIsDevKit());
  fprintf(fp, "    sceKernelIsTestKit() = %d\n", sceKernelIsTestKit());
  fprintf(fp, "    sceKernelIsCEX()     = %d\n", sceKernelIsCEX());

  /* Read all interesting values again */
  fprintf(fp, "\n  After all changes:\n");
  for(int i = 0; indices[i] >= 0; i++) {
    struct dipsw_read_req req = { .index = indices[i], .pad = 0, .value = 0 };
    ioctl(fd, DIPSW_IOCTL_READ, &req);
    fprintf(fp, "    dipsw[0x%02x] = 0x%08x\n", indices[i], req.value);
  }

  close(fd);
}

/* Phase 3: Find and patch machdep.check_genuine_devkit_for_psm sysctl.
 *
 * Strategy: The sysctl value is stored in kernel data. We know its
 * current value (0). We'll scan kernel data near SECURITY_FLAGS for
 * the sysctl's backing variable and change it to 1.
 *
 * FreeBSD sysctl nodes are stored in a tree of sysctl_oid structures.
 * Each has: name, handler function, and for integer types, a pointer
 * to the backing variable. We can find the string
 * "check_genuine_devkit_for_psm" in kernel data and use it to find
 * the sysctl_oid, then follow the pointer to the variable. */
static void
patch_sysctl_genuine_devkit(FILE *fp) {
  fprintf(fp, "\n=== SYSCTL GENUINE DEVKIT PATCH ===\n\n");

  int cur_val = -1;
  size_t len = sizeof(cur_val);
  int err = sysctlbyname("machdep.check_genuine_devkit_for_psm",
                          &cur_val, &len, NULL, 0);
  fprintf(fp, "  Current machdep.check_genuine_devkit_for_psm = %d (err=%d)\n",
          cur_val, err);
  if(err) { fprintf(fp, "  ERROR: sysctl not available\n"); return; }

  intptr_t kdata = KERNEL_ADDRESS_DATA_BASE;
  intptr_t ktext = KERNEL_ADDRESS_TEXT_BASE;
  if(!kdata || !ktext) {
    fprintf(fp, "  ERROR: kernel base not available\n"); return;
  }

  /* Find "check_genuine_devkit_for_psm" string in kernel data */
  const char *needle = "check_genuine_devkit_for_psm";
  size_t nlen = strlen(needle);
  size_t chunk_sz = 256 * 1024;
  unsigned char *buf = malloc(chunk_sz);
  if(!buf) return;

  intptr_t string_addr = 0;
  for(size_t off = 0; off < 64UL * 1024 * 1024; off += chunk_sz) {
    if(kernel_copyout(kdata + off, buf, chunk_sz)) break;
    for(size_t i = 0; i + nlen < chunk_sz; i++) {
      if(!memcmp(&buf[i], needle, nlen) && buf[i + nlen] == 0) {
        string_addr = kdata + off + i;
        goto found_string;
      }
    }
  }
  fprintf(fp, "  String not found\n"); free(buf); return;

found_string:
  fprintf(fp, "  String at 0x%lx\n", (unsigned long)string_addr);

  /* Find pointer to string (oid_name field in sysctl_oid) */
  intptr_t name_addr = 0;
  for(size_t off = 0; off < 64UL * 1024 * 1024; off += chunk_sz) {
    if(kernel_copyout(kdata + off, buf, chunk_sz)) break;
    for(size_t i = 0; i + 8 <= chunk_sz; i += 8) {
      if(*(intptr_t *)&buf[i] == string_addr) {
        name_addr = kdata + off + i;
        goto found_oid;
      }
    }
  }
  fprintf(fp, "  sysctl_oid not found\n"); free(buf); return;

found_oid:;
  /* sysctl_oid layout: oid_name at +0x30, oid_handler at +0x38 */
  intptr_t struct_base = name_addr - 0x30;
  fprintf(fp, "  sysctl_oid @ 0x%lx\n", (unsigned long)struct_base);

  intptr_t oid_handler = 0;
  kernel_copyout(struct_base + 0x38, &oid_handler, 8);
  fprintf(fp, "  oid_handler = 0x%lx\n", (unsigned long)oid_handler);

  /* Dump handler code (128 bytes) */
  fprintf(fp, "\n  Handler code at 0x%lx:\n", (unsigned long)oid_handler);
  unsigned char hcode[128];
  if(!kernel_copyout(oid_handler, hcode, sizeof(hcode))) {
    for(int row = 0; row < 128; row += 16) {
      fprintf(fp, "    +%02x: ", row);
      for(int c = 0; c < 16; c++)
        fprintf(fp, "%02x ", hcode[row + c]);
      fprintf(fp, "\n");
    }
  } else {
    fprintf(fp, "    (cannot read handler code)\n");
  }

  /* Find sysctl_handle_int by looking at a known standard sysctl.
   * kern.osreldate is a CTLTYPE_INT that uses sysctl_handle_int.
   * We find it by scanning for the string "osreldate". */
  fprintf(fp, "\n  Searching for sysctl_handle_int via kern.osreldate...\n");

  intptr_t std_handler = 0;
  const char *ref_needle = "osreldate";
  size_t ref_nlen = strlen(ref_needle);
  intptr_t ref_string = 0;

  for(size_t off = 0; off < 64UL * 1024 * 1024; off += chunk_sz) {
    if(kernel_copyout(kdata + off, buf, chunk_sz)) break;
    for(size_t i = 0; i + ref_nlen < chunk_sz; i++) {
      if(!memcmp(&buf[i], ref_needle, ref_nlen) && buf[i + ref_nlen] == 0) {
        /* Make sure it's exactly "osreldate" not a substring */
        if(i > 0 && buf[i-1] != 0) continue;
        ref_string = kdata + off + i;
        goto found_ref_string;
      }
    }
  }
  fprintf(fp, "  Could not find osreldate string\n");
  goto try_handler_patch;

found_ref_string:
  fprintf(fp, "  osreldate string at 0x%lx\n", (unsigned long)ref_string);

  for(size_t off = 0; off < 64UL * 1024 * 1024; off += chunk_sz) {
    if(kernel_copyout(kdata + off, buf, chunk_sz)) break;
    for(size_t i = 0; i + 8 <= chunk_sz; i += 8) {
      if(*(intptr_t *)&buf[i] == ref_string) {
        intptr_t ref_name_addr = kdata + off + i;
        intptr_t ref_base = ref_name_addr - 0x30;
        kernel_copyout(ref_base + 0x38, &std_handler, 8);
        fprintf(fp, "  osreldate sysctl_oid @ 0x%lx, handler = 0x%lx\n",
                (unsigned long)ref_base, (unsigned long)std_handler);

        /* Dump its code too for comparison */
        unsigned char scode[64];
        if(!kernel_copyout(std_handler, scode, sizeof(scode))) {
          fprintf(fp, "  sysctl_handle_int code:\n    ");
          for(int c = 0; c < 32; c++)
            fprintf(fp, "%02x ", scode[c]);
          fprintf(fp, "\n    ");
          for(int c = 32; c < 64; c++)
            fprintf(fp, "%02x ", scode[c]);
          fprintf(fp, "\n");
        }
        goto found_std_handler;
      }
    }
  }
  fprintf(fp, "  Could not find osreldate sysctl_oid\n");
  goto try_handler_patch;

found_std_handler:
  fprintf(fp, "\n  === HANDLER SWAP: custom -> sysctl_handle_int ===\n");
  fprintf(fp, "  Setting oid_arg1=NULL, oid_arg2=1, handler=0x%lx\n",
          (unsigned long)std_handler);

  /* Set oid_arg2 = 1 (value to return) */
  int64_t arg2_val = 1;
  kernel_copyin(&arg2_val, struct_base + 0x28, 8);

  /* Ensure oid_arg1 = NULL */
  intptr_t null_ptr = 0;
  kernel_copyin(&null_ptr, struct_base + 0x20, 8);

  /* Swap handler to sysctl_handle_int */
  kernel_copyin(&std_handler, struct_base + 0x38, 8);

  /* Also make it RW so we can verify */
  uint32_t rw_kind = 0xC0000002; /* CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_WR */
  kernel_copyin(&rw_kind, struct_base + 0x18 + 4, 4);

  int check = -1;
  size_t clen = sizeof(check);
  sysctlbyname("machdep.check_genuine_devkit_for_psm", &check, &clen, NULL, 0);
  fprintf(fp, "  After handler swap: machdep.check_genuine_devkit_for_psm = %d\n",
          check);

  if(check == 1) {
    fprintf(fp, "  *** SUCCESS! sysctl patched via handler swap ***\n");
    goto patched;
  }

  fprintf(fp, "  Handler swap didn't work, handler may use different offset\n");

  /* Try other possible handler offsets in the struct */
  int offsets_to_try[] = { 0x28, 0x38, 0x40, 0x48 };
  for(int t = 0; t < 4; t++) {
    int hoff = offsets_to_try[t];
    if(hoff == 0x38) continue; /* already tried */

    intptr_t test_handler = 0;
    kernel_copyout(struct_base + hoff, &test_handler, 8);
    if(test_handler == oid_handler) {
      fprintf(fp, "  Found handler at struct+0x%x too, swapping\n", hoff);
      kernel_copyin(&std_handler, struct_base + hoff, 8);

      check = -1;
      clen = sizeof(check);
      sysctlbyname("machdep.check_genuine_devkit_for_psm",
                    &check, &clen, NULL, 0);
      fprintf(fp, "  After swap at +0x%x: value = %d\n", hoff, check);
      if(check == 1) {
        fprintf(fp, "  *** SUCCESS! ***\n");
        goto patched;
      }
    }
  }

try_handler_patch:
  /* Last resort: patch the handler function itself.
   * A sysctl handler signature is:
   *   int handler(struct sysctl_oid *oidp, void *arg1,
   *               intmax_t arg2, struct sysctl_req *req)
   * The handler calls sysctl_handle_int internally.
   * We look for patterns in the handler code that produce the 0 return. */
  fprintf(fp, "\n  === DIRECT HANDLER CODE ANALYSIS ===\n");

  if(kernel_copyout(oid_handler, hcode, sizeof(hcode))) {
    fprintf(fp, "  Cannot read handler code\n");
    goto done;
  }

  /* Look for xor eax,eax (31 c0) or mov eax,0 (b8 00 00 00 00)
   * near the end of the function (before ret c3).
   * These are where the handler sets the return value to 0.
   * Also look for mov dword ptr [rbp-XX], 0 patterns which
   * set a local variable to 0 before passing to sysctl_handle_int.
   *
   * Common pattern in custom handlers:
   *   mov dword ptr [rbp-N], 0    ; val = 0
   *   lea rsi, [rbp-N]            ; &val
   *   mov edx, 4                  ; sizeof(int)
   *   ...
   *   call sysctl_handle_int / SYSCTL_OUT
   *
   * We want to change the 0 to 1. */

  /* Find c7 45 XX 00 00 00 00 (mov dword [rbp-XX], 0) and change to 1 */
  int patched_handler = 0;
  for(int pc = 0; pc < 120; pc++) {
    /* mov dword ptr [rbp+disp8], 0 = c7 45 XX 00 00 00 00 */
    if(hcode[pc] == 0xc7 && hcode[pc+1] == 0x45 &&
       hcode[pc+3] == 0x00 && hcode[pc+4] == 0x00 &&
       hcode[pc+5] == 0x00 && hcode[pc+6] == 0x00) {
      fprintf(fp, "  Found 'mov dword [rbp%+d], 0' at handler+0x%x\n",
              (int8_t)hcode[pc+2], pc);
      unsigned char patch = 0x01;
      kernel_copyin(&patch, oid_handler + pc + 3, 1);
      patched_handler = 1;

      int check3 = -1;
      size_t clen3 = sizeof(check3);
      sysctlbyname("machdep.check_genuine_devkit_for_psm",
                    &check3, &clen3, NULL, 0);
      fprintf(fp, "  After handler code patch: value = %d\n", check3);
      if(check3 == 1) {
        fprintf(fp, "  *** SUCCESS! Handler code patched ***\n");
        goto patched;
      }
    }
    /* mov dword ptr [rsp+disp8], 0 = c7 44 24 XX 00 00 00 00 */
    if(pc < 119 && hcode[pc] == 0xc7 && hcode[pc+1] == 0x44 &&
       hcode[pc+2] == 0x24 &&
       hcode[pc+4] == 0x00 && hcode[pc+5] == 0x00 &&
       hcode[pc+6] == 0x00 && hcode[pc+7] == 0x00) {
      fprintf(fp, "  Found 'mov dword [rsp+0x%02x], 0' at handler+0x%x\n",
              hcode[pc+3], pc);
      unsigned char patch = 0x01;
      kernel_copyin(&patch, oid_handler + pc + 4, 1);
      patched_handler = 1;

      int check3 = -1;
      size_t clen3 = sizeof(check3);
      sysctlbyname("machdep.check_genuine_devkit_for_psm",
                    &check3, &clen3, NULL, 0);
      fprintf(fp, "  After handler code patch: value = %d\n", check3);
      if(check3 == 1) {
        fprintf(fp, "  *** SUCCESS! Handler code patched ***\n");
        goto patched;
      }
    }
    /* xor eax,eax (31 c0) followed soon by a call or ret -
     * this might set the value before SYSCTL_OUT */
    if(hcode[pc] == 0x31 && hcode[pc+1] == 0xc0 && !patched_handler) {
      fprintf(fp, "  Found 'xor eax,eax' at handler+0x%x\n", pc);
    }
  }

  /* Also dump the handler's full disassembly as hex for analysis */
  fprintf(fp, "\n  Full handler hex (256 bytes):\n");
  unsigned char hcode2[256];
  kernel_copyout(oid_handler, hcode2, sizeof(hcode2));
  for(int row = 0; row < 256; row += 16) {
    fprintf(fp, "    +%02x: ", row);
    for(int c = 0; c < 16; c++)
      fprintf(fp, "%02x ", hcode2[row + c]);
    fprintf(fp, "\n");
  }

  free(buf);
  return;

done:
  free(buf);
  return;

patched:
  free(buf);
  fprintf(fp, "\n=== SYSCTL PATCHED SUCCESSFULLY ===\n");
  fprintf(fp, "  machdep.check_genuine_devkit_for_psm = 1\n");
}

/* Phase 4: Patch sceKernelIsDevKit in SceShellUI + SceShellCore */
static void
patch_isdevkit_stubs(FILE *fp) {
  fprintf(fp, "\n=== ISDEVKIT STUB PATCHES ===\n\n");

  pid_t pids[2];
  const char *names[2] = { "SceShellUI", "SceShellCore" };
  pids[0] = find_process("SceShellUI");
  pids[1] = find_process("SceShellCore");

  for(int p = 0; p < 2; p++) {
    if(pids[p] < 0) continue;
    fprintf(fp, "  %s (PID %d):\n", names[p], pids[p]);

    uint32_t lk_handle = 0;
    if(kernel_dynlib_handle(pids[p], "libkernel_sys.sprx", &lk_handle))
      continue;

    intptr_t addrs[3];
    addrs[0] = kernel_dynlib_dlsym(pids[p], lk_handle, "sceKernelIsDevKit");
    addrs[1] = kernel_dynlib_dlsym(pids[p], lk_handle, "sceKernelIsTestKit");
    addrs[2] = kernel_dynlib_dlsym(pids[p], lk_handle, "sceKernelIsCEX");

    const char *func_names[3] = { "IsDevKit", "IsTestKit", "IsCEX" };
    /* IsDevKit=return 1, IsTestKit=return 1, IsCEX=return 0 */
    unsigned char patches[3][6] = {
      { 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3 },
      { 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3 },
      { 0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90 }
    };
    int sizes[3] = { 6, 6, 3 };

    for(int f = 0; f < 3; f++) {
      if(!addrs[f]) continue;

      /* Check if already patched */
      unsigned char cur[6];
      kernel_proc_copyout(pids[p], addrs[f], cur, 6);
      if(cur[0] == patches[f][0] && cur[1] == patches[f][1]) {
        fprintf(fp, "    %s already patched\n", func_names[f]);
        continue;
      }

      kernel_set_vmem_protection(pids[p], addrs[f], 4096, 7);
      int ret = kernel_proc_copyin(pids[p], patches[f], addrs[f], sizes[f]);
      fprintf(fp, "    %s @ 0x%lx: patch ret=%d\n",
              func_names[f], (unsigned long)addrs[f], ret);
    }
  }
}

int
main(void) {
  mkdir(OUT_DIR, 0777);
  elevate();
  notify("devkitact: starting...");
  printf("devkitact: elevated\n");

  char path[256];
  snprintf(path, sizeof(path), "%s/devkitact.txt", OUT_DIR);
  FILE *fp = fopen(path, "w");
  if(!fp) { perror(path); return 1; }

  fprintf(fp, "=== DEVKIT ACTIVATION ===\n\n");
  fprintf(fp, "Pre-state:\n");
  fprintf(fp, "  sceKernelIsDevKit()  = %d\n", sceKernelIsDevKit());
  fprintf(fp, "  sceKernelIsTestKit() = %d\n", sceKernelIsTestKit());
  fprintf(fp, "  sceKernelIsCEX()     = %d\n", sceKernelIsCEX());
  fprintf(fp, "  SECURITY_FLAGS = 0x%02x\n",
          kernel_getchar(KERNEL_ADDRESS_SECURITY_FLAGS));
  fprintf(fp, "  TARGETID = 0x%02x\n",
          kernel_getchar(KERNEL_ADDRESS_TARGETID));

  int gdev = -1; size_t glen = sizeof(gdev);
  sysctlbyname("machdep.check_genuine_devkit_for_psm", &gdev, &glen, NULL, 0);
  fprintf(fp, "  machdep.check_genuine_devkit_for_psm = %d\n\n", gdev);

  /* Phase 1: Read dipsw */
  printf("devkitact: phase 1 - read dipsw\n");
  read_all_dipsw(fp);

  /* Phase 2: Try setting dipsw flags */
  printf("devkitact: phase 2 - set dipsw flags\n");
  notify("devkitact: setting dipsw flags...");
  try_set_dipsw_flags(fp);

  /* Phase 3: Patch sysctl */
  printf("devkitact: phase 3 - patch sysctl\n");
  notify("devkitact: patching sysctl...");
  patch_sysctl_genuine_devkit(fp);

  /* Phase 4: Patch IsDevKit stubs */
  printf("devkitact: phase 4 - patch stubs\n");
  patch_isdevkit_stubs(fp);

  /* Final state */
  fprintf(fp, "\n=== FINAL STATE ===\n");
  fprintf(fp, "  sceKernelIsDevKit()  = %d\n", sceKernelIsDevKit());
  fprintf(fp, "  sceKernelIsTestKit() = %d\n", sceKernelIsTestKit());
  fprintf(fp, "  sceKernelIsCEX()     = %d\n", sceKernelIsCEX());

  gdev = -1; glen = sizeof(gdev);
  sysctlbyname("machdep.check_genuine_devkit_for_psm", &gdev, &glen, NULL, 0);
  fprintf(fp, "  machdep.check_genuine_devkit_for_psm = %d\n", gdev);

  fprintf(fp, "\n=== NEXT STEPS ===\n");
  fprintf(fp, "If machdep.check_genuine_devkit_for_psm = 1 and\n");
  fprintf(fp, "sceKernelIsDevKit() = 1, try restarting SceShellUI\n");
  fprintf(fp, "(killshell.elf) and re-running this payload immediately\n");
  fprintf(fp, "after to re-patch the stubs before ShellUI fully loads.\n");

  fclose(fp);
  printf("devkitact: wrote %s\n", path);
  notify("devkitact: done - check results");
  printf("devkitact: done\n");
  return 0;
}
