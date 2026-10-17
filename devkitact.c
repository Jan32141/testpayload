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
static intptr_t
resolve_trampoline(intptr_t tramp_addr, FILE *fp) {
  unsigned char code[8];
  if(kernel_copyout(tramp_addr, code, 8)) return 0;
  if(code[0] == 0xe9) {
    int32_t rel = *(int32_t *)&code[1];
    intptr_t target = tramp_addr + 5 + rel;
    fprintf(fp, "  Trampoline at 0x%lx: jmp rel32 -> 0x%lx\n",
            (unsigned long)tramp_addr, (unsigned long)target);
    return target;
  }
  if(code[0] == 0xff && code[1] == 0x25) {
    int32_t rip_off = *(int32_t *)&code[2];
    intptr_t ptr_addr = tramp_addr + 6 + rip_off;
    intptr_t target = 0;
    kernel_copyout(ptr_addr, &target, 8);
    fprintf(fp, "  Trampoline at 0x%lx: jmp [rip+0x%x] -> 0x%lx\n",
            (unsigned long)tramp_addr, rip_off, (unsigned long)target);
    return target;
  }
  fprintf(fp, "  Not a trampoline (first bytes: %02x %02x %02x %02x)\n",
          code[0], code[1], code[2], code[3]);
  return tramp_addr;
}

static int
verify_write8(intptr_t addr, intptr_t expected, FILE *fp) {
  intptr_t readback = 0;
  kernel_copyout(addr, &readback, 8);
  if(readback == expected) {
    fprintf(fp, "  Write verified at 0x%lx = 0x%lx\n",
            (unsigned long)addr, (unsigned long)expected);
    return 1;
  }
  fprintf(fp, "  Write FAILED at 0x%lx: expected 0x%lx, got 0x%lx\n",
          (unsigned long)addr, (unsigned long)expected,
          (unsigned long)readback);
  return 0;
}

static int
verify_write4(intptr_t addr, uint32_t expected, FILE *fp) {
  uint32_t readback = 0;
  kernel_copyout(addr, &readback, 4);
  if(readback == expected) {
    fprintf(fp, "  Write verified at 0x%lx = 0x%x\n",
            (unsigned long)addr, expected);
    return 1;
  }
  fprintf(fp, "  Write FAILED at 0x%lx: expected 0x%x, got 0x%x\n",
          (unsigned long)addr, expected, readback);
  return 0;
}

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
  intptr_t struct_base = name_addr - 0x30;
  fprintf(fp, "  sysctl_oid @ 0x%lx\n", (unsigned long)struct_base);

  intptr_t oid_handler_tramp = 0;
  kernel_copyout(struct_base + 0x38, &oid_handler_tramp, 8);
  fprintf(fp, "  oid_handler (trampoline) = 0x%lx\n",
          (unsigned long)oid_handler_tramp);

  intptr_t real_handler = resolve_trampoline(oid_handler_tramp, fp);
  if(!real_handler) {
    fprintf(fp, "  ERROR: cannot resolve handler trampoline\n");
    free(buf); return;
  }

  /* Dump 512 bytes of REAL handler code */
  fprintf(fp, "\n  === REAL HANDLER CODE at 0x%lx ===\n",
          (unsigned long)real_handler);
  unsigned char rcode[512];
  if(kernel_copyout(real_handler, rcode, sizeof(rcode))) {
    fprintf(fp, "  Cannot read real handler code\n");
    free(buf); return;
  }
  for(int row = 0; row < 512; row += 16) {
    fprintf(fp, "    +%02x: ", row);
    for(int c = 0; c < 16; c++)
      fprintf(fp, "%02x ", rcode[row + c]);
    fprintf(fp, "\n");
  }

  /* Find sysctl_handle_int via kern.osreldate */
  fprintf(fp, "\n  === Finding sysctl_handle_int via kern.osreldate ===\n");
  intptr_t std_handler_tramp = 0;
  intptr_t real_std_handler = 0;
  const char *ref_needle = "osreldate";
  size_t ref_nlen = strlen(ref_needle);
  intptr_t ref_string = 0;

  for(size_t off = 0; off < 64UL * 1024 * 1024; off += chunk_sz) {
    if(kernel_copyout(kdata + off, buf, chunk_sz)) break;
    for(size_t i = 0; i + ref_nlen < chunk_sz; i++) {
      if(!memcmp(&buf[i], ref_needle, ref_nlen) && buf[i + ref_nlen] == 0) {
        if(i > 0 && buf[i-1] != 0) continue;
        ref_string = kdata + off + i;
        goto found_ref_string;
      }
    }
  }
  fprintf(fp, "  Could not find osreldate string\n");
  goto try_code_patch;

found_ref_string:
  fprintf(fp, "  osreldate string at 0x%lx\n", (unsigned long)ref_string);

  for(size_t off = 0; off < 64UL * 1024 * 1024; off += chunk_sz) {
    if(kernel_copyout(kdata + off, buf, chunk_sz)) break;
    for(size_t i = 0; i + 8 <= chunk_sz; i += 8) {
      if(*(intptr_t *)&buf[i] == ref_string) {
        intptr_t ref_name_addr = kdata + off + i;
        intptr_t ref_base = ref_name_addr - 0x30;
        kernel_copyout(ref_base + 0x38, &std_handler_tramp, 8);
        fprintf(fp, "  osreldate oid @ 0x%lx, handler tramp = 0x%lx\n",
                (unsigned long)ref_base, (unsigned long)std_handler_tramp);
        real_std_handler = resolve_trampoline(std_handler_tramp, fp);
        fprintf(fp, "  REAL sysctl_handle_int = 0x%lx\n",
                (unsigned long)real_std_handler);
        goto found_std_handler;
      }
    }
  }
  fprintf(fp, "  Could not find osreldate sysctl_oid\n");
  goto try_code_patch;

found_std_handler:;
  /* Strategy A: Write real sysctl_handle_int address directly to handler
   * field in sysctl_oid (data segment, safe to write).
   * Set arg1=NULL, arg2=1 so sysctl_handle_int returns 1.
   * NOTE: Do NOT write to trampoline code (text segment) - causes panic. */
  fprintf(fp, "\n  === STRATEGY A: Direct handler pointer swap ===\n");

  intptr_t arg1_val = 0;
  int64_t arg2_val = 1;
  fprintf(fp, "  Setting oid_arg1=NULL, oid_arg2=1\n");
  kernel_copyin(&arg1_val, struct_base + 0x20, 8);
  kernel_copyin(&arg2_val, struct_base + 0x28, 8);
  verify_write8(struct_base + 0x20, 0, fp);
  verify_write8(struct_base + 0x28, 1, fp);

  uint32_t rw_kind = 0xC0000002;
  kernel_copyin(&rw_kind, struct_base + 0x18 + 4, 4);
  verify_write4(struct_base + 0x18 + 4, rw_kind, fp);

  /* Write REAL sysctl_handle_int (not trampoline) to handler field */
  fprintf(fp, "  Writing real sysctl_handle_int 0x%lx to oid_handler\n",
          (unsigned long)real_std_handler);
  kernel_copyin(&real_std_handler, struct_base + 0x38, 8);
  verify_write8(struct_base + 0x38, real_std_handler, fp);

  int check = -1;
  size_t clen = sizeof(check);
  sysctlbyname("machdep.check_genuine_devkit_for_psm", &check, &clen, NULL, 0);
  fprintf(fp, "  After direct handler swap: value = %d\n", check);

  if(check == 1) {
    fprintf(fp, "  *** SUCCESS via direct handler pointer! ***\n");
    goto patched;
  }

  /* Strategy A2: Try writing osreldate's trampoline address instead.
   * This worked before (returned 900000) - if the dispatch requires
   * going through a trampoline, this confirms the mechanism. */
  fprintf(fp, "\n  === STRATEGY A2: Write osreldate trampoline to handler ===\n");
  fprintf(fp, "  Writing std_handler_tramp 0x%lx to oid_handler\n",
          (unsigned long)std_handler_tramp);
  kernel_copyin(&std_handler_tramp, struct_base + 0x38, 8);
  verify_write8(struct_base + 0x38, std_handler_tramp, fp);

  check = -1; clen = sizeof(check);
  sysctlbyname("machdep.check_genuine_devkit_for_psm", &check, &clen, NULL, 0);
  fprintf(fp, "  After osreldate trampoline swap: value = %d\n", check);

  if(check == 1) {
    fprintf(fp, "  *** SUCCESS! ***\n");
    goto patched;
  }

  /* Restore original handler */
  kernel_copyin(&oid_handler_tramp, struct_base + 0x38, 8);

  /* Strategy A3: The handler might read the value from a global variable.
   * Let's look at what the real handler actually does by examining if it
   * reads from a fixed kernel data address. We search the handler for
   * mov/lea with RIP-relative addressing that points to data segment. */
  fprintf(fp, "\n  === STRATEGY A3: Find data references in real handler ===\n");
  for(int pc = 0; pc < 500; pc++) {
    /* Look for RIP-relative loads: XX XX XX XX [rip+disp32]
     * Common patterns:
     *   8b 05 XX XX XX XX = mov eax, [rip+disp32]
     *   8b 0d XX XX XX XX = mov ecx, [rip+disp32]
     *   48 8b XX XX XX XX XX = mov rXX, [rip+disp32]
     *   48 8d XX XX XX XX XX = lea rXX, [rip+disp32] */

    /* mov eax/ecx/edx/ebx, [rip+disp32] = 8b (00-1d) with modrm=05/0d/15/1d */
    if(rcode[pc] == 0x8b && (rcode[pc+1] & 0xc7) == 0x05) {
      int32_t disp = *(int32_t *)&rcode[pc+2];
      intptr_t target = real_handler + pc + 6 + disp;
      int reg = (rcode[pc+1] >> 3) & 7;
      const char *rnames[] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi"};
      fprintf(fp, "  [%03x] mov %s, [rip+0x%x] -> 0x%lx",
              pc, rnames[reg], disp, (unsigned long)target);
      /* Read the value at that address */
      if(target >= kdata && target < kdata + 64UL*1024*1024) {
        int32_t val = 0;
        kernel_copyout(target, &val, 4);
        fprintf(fp, " (value=%d/0x%x)", val, val);
        if(val == 0) {
          fprintf(fp, " <- CANDIDATE! Trying patch to 1...");
          int32_t one = 1;
          kernel_copyin(&one, target, 4);
          verify_write4(target, 1, fp);

          int ch = -1; size_t cl = sizeof(ch);
          sysctlbyname("machdep.check_genuine_devkit_for_psm", &ch, &cl, NULL, 0);
          fprintf(fp, "\n    -> sysctl = %d\n", ch);
          if(ch == 1) {
            fprintf(fp, "  *** SUCCESS via data variable patch! ***\n");
            goto patched;
          }
          int32_t z = 0;
          kernel_copyin(&z, target, 4);
        }
      }
      fprintf(fp, "\n");
    }

    /* 48 8b XX [rip+disp32] with REX.W prefix */
    if(rcode[pc] == 0x48 && rcode[pc+1] == 0x8b &&
       (rcode[pc+2] & 0xc7) == 0x05) {
      int32_t disp = *(int32_t *)&rcode[pc+3];
      intptr_t target = real_handler + pc + 7 + disp;
      int reg = (rcode[pc+2] >> 3) & 7;
      const char *rnames[] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"};
      fprintf(fp, "  [%03x] mov %s, [rip+0x%x] -> 0x%lx\n",
              pc, rnames[reg], disp, (unsigned long)target);
    }
  }

try_code_patch:;
  /* Strategy B: Analyze calls in real handler (read-only).
   * NOTE: We do NOT write to handler code (text segment) - would panic. */
  fprintf(fp, "\n  === STRATEGY B: Analyze calls in real handler ===\n");
  for(int pc = 0; pc < 507; pc++) {
    if(rcode[pc] == 0xe8) {
      int32_t rel = *(int32_t *)&rcode[pc + 1];
      intptr_t call_target = real_handler + pc + 5 + rel;
      fprintf(fp, "  [%03x] call 0x%lx", pc, (unsigned long)call_target);
      if(real_std_handler && call_target == real_std_handler)
        fprintf(fp, " <-- sysctl_handle_int!");
      fprintf(fp, "\n");
    }
  }

  /* Strategy C: Analyze code patterns (read-only, for diagnostics) */
  fprintf(fp, "\n  === STRATEGY C: Code pattern analysis (read-only) ===\n");
  for(int pc = 0; pc < 500; pc++) {
    if(rcode[pc] == 0xc7 && rcode[pc+1] == 0x45 &&
       rcode[pc+3] == 0x00 && rcode[pc+4] == 0x00 &&
       rcode[pc+5] == 0x00 && rcode[pc+6] == 0x00) {
      fprintf(fp, "  [%03x] mov dword [rbp%+d], 0\n",
              pc, (int8_t)rcode[pc+2]);
    }
    if(pc < 498 && rcode[pc] == 0xc7 && rcode[pc+1] == 0x44 &&
       rcode[pc+2] == 0x24 &&
       rcode[pc+4] == 0x00 && rcode[pc+5] == 0x00 &&
       rcode[pc+6] == 0x00 && rcode[pc+7] == 0x00) {
      fprintf(fp, "  [%03x] mov dword [rsp+0x%02x], 0\n",
              pc, rcode[pc+3]);
    }
    if(rcode[pc] == 0x31 && rcode[pc+1] == 0xc0) {
      fprintf(fp, "  [%03x] xor eax,eax (next: %02x)\n",
              pc, pc+2 < 512 ? rcode[pc+2] : 0);
    }
    if(rcode[pc] == 0xb8 && rcode[pc+1] == 0x00 && rcode[pc+2] == 0x00 &&
       rcode[pc+3] == 0x00 && rcode[pc+4] == 0x00) {
      fprintf(fp, "  [%03x] mov eax, 0\n", pc);
    }
  }

  fprintf(fp, "\n  === ALL SAFE STRATEGIES EXHAUSTED ===\n");
  fprintf(fp, "  (Text segment writes skipped to avoid kernel panic)\n");
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
