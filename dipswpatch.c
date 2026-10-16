/* DIP switch reader + kernel patch to enable devkit panel.
 * Strategy:
 * 1. Read all DIP switches via /dev/dipsw ioctl
 * 2. Try writing DIP switches for devkit identification
 * 3. Patch sceKernelIsDevKit() return value in kernel text
 * 4. Try sceShellCoreUtilSetGnmCompositorOnScreenProfilerFlag
 * 5. Restart SceShellUI so it re-evaluates flags
 *
 * SAFETY: NEVER touches IDU mode. */
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

/* SCE syscalls */
int sceKernelGetProcessName(pid_t, char *);
int sceKernelIsDevKit(void);
int sceKernelIsTestKit(void);
int sceKernelIsCEX(void);

int sceRegMgrGetInt(unsigned int regId, int *value);
int sceRegMgrSetInt(unsigned int regId, int value);

/* IPMI for calling SceShellCore functions */
int sceSystemServiceLoadExec(const char *path, const char *args[]);

/* DIP switch ioctl commands - based on FreeBSD/PS5 convention
 * libSceDipsw uses open("/dev/dipsw") + ioctl
 * ioctl read: _IOR('d', index, uint32_t)  -> reads dipsw[index]
 * ioctl write: _IOW('d', index, uint32_t) -> writes dipsw[index] */
#define DIPSW_IOCTL_READ(idx)  _IOR('d', (idx), uint32_t)
#define DIPSW_IOCTL_WRITE(idx) _IOW('d', (idx), uint32_t)

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

/* Phase 1: Read all DIP switches */
static void
read_dipsw(FILE *fp) {
  fprintf(fp, "=== DIP SWITCH DUMP ===\n\n");
  printf("dipswpatch: reading DIP switches...\n");

  int fd = open("/dev/dipsw", O_RDWR);
  if(fd < 0) {
    fd = open("/dev/dipsw", O_RDONLY);
  }
  if(fd < 0) {
    fprintf(fp, "  /dev/dipsw: cannot open (err=%d)\n", fd);
    printf("dipswpatch: cannot open /dev/dipsw\n");

    /* Try alternative: read via kernel memory directly.
     * On FreeBSD/PS5 dipsw values may be stored in a kernel array. */
    fprintf(fp, "  Trying kernel memory approach...\n");
    return;
  }

  fprintf(fp, "  /dev/dipsw opened (fd=%d)\n\n", fd);

  /* Try reading dipsw indices 0x00 through 0xFF */
  fprintf(fp, "  --- Read via ioctl _IOR('d', idx, uint32_t) ---\n");
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

  /* Also try with simple read at offset */
  fprintf(fp, "\n  --- Read via plain ioctl(fd, idx, &val) ---\n");
  for(int idx = 0; idx < 256; idx++) {
    uint32_t val = 0;
    int err = ioctl(fd, idx, &val);
    if(!err && (val != 0 || idx < 16)) {
      fprintf(fp, "  ioctl(%d) = 0x%08x (%u)\n", idx, val, val);
      found_any = 1;
    }
  }

  /* Try lseek + read approach */
  fprintf(fp, "\n  --- Read via lseek+read ---\n");
  for(int idx = 0; idx < 64; idx++) {
    uint32_t val = 0;
    if(lseek(fd, idx * 4, SEEK_SET) >= 0) {
      ssize_t n = read(fd, &val, sizeof(val));
      if(n == sizeof(val)) {
        fprintf(fp, "  offset[%d] = 0x%08x (%u)\n", idx, val, val);
        found_any = 1;
      }
    }
  }

  if(!found_any) {
    fprintf(fp, "  No DIP switch values could be read\n");
  }

  close(fd);
}

/* Phase 2: Scan kernel text for sceKernelIsDevKit/IsTestKit functions
 * and patch their return values.
 *
 * sceKernelIsDevKit() in kernel likely looks like:
 *   mov eax, <value from dipsw check>
 *   ret
 * Or it reads from a global.
 *
 * Strategy: Find the kernel function by scanning kernel text for the
 * pattern that reads the dipsw/identification bytes and returns 0/1.
 * Then patch it to always return 1. */
static void
patch_kernel_isdevkit(FILE *fp) {
  fprintf(fp, "\n=== KERNEL PATCH ATTEMPT ===\n\n");

  intptr_t ktext = KERNEL_ADDRESS_TEXT_BASE;
  intptr_t kdata = KERNEL_ADDRESS_DATA_BASE;
  fprintf(fp, "  KERNEL_TEXT_BASE = 0x%lx\n", (unsigned long)ktext);
  fprintf(fp, "  KERNEL_DATA_BASE = 0x%lx\n", (unsigned long)kdata);

  if(!ktext) {
    fprintf(fp, "  ERROR: kernel text base not available\n");
    return;
  }

  /* First, let's find where the kernel stores the IsDevKit result.
   * sceKernelIsDevKit is a syscall that reads from a kernel global.
   * On PS5/FreeBSD, the kernel has a global variable for this.
   *
   * Approach: scan kernel data segment for a byte that represents
   * the devkit flag (currently 0), find its xrefs in text, and patch. */

  /* Check current values first */
  int isdev_before = sceKernelIsDevKit();
  int istest_before = sceKernelIsTestKit();
  fprintf(fp, "  Before patch:\n");
  fprintf(fp, "    sceKernelIsDevKit()  = %d\n", isdev_before);
  fprintf(fp, "    sceKernelIsTestKit() = %d\n", istest_before);

  /* Scan kernel text for the sceKernelIsDevKit syscall handler.
   * On PS5 FW 13.00, we'll look for common x86_64 patterns:
   *
   * The function likely:
   * 1. Reads a byte from a kernel data address
   * 2. Tests/compares it
   * 3. Returns 0 or 1
   *
   * Common pattern: xor eax,eax; ret  (31 c0 c3) for "return 0"
   * We want to change to: mov eax,1; ret  (b8 01 00 00 00 c3)
   *
   * But we need to find the RIGHT function. Let's scan for the
   * pattern near references to the security flags or TARGETID. */

  /* Alternative approach: scan kernel data for a "device type" variable
   * that stores 0 (CEX) and change it to 2 (devkit) or 0x82 (testkit).
   *
   * The targetID is at KERNEL_ADDRESS_TARGETID. We already know it's 0x82.
   * sceKernelIsDevKit() probably checks: (targetid & 0x3) == 0x02
   * sceKernelIsTestKit() probably checks: targetid >= 0x80
   *
   * But it returns 0 despite TARGETID being 0x82! This means it's
   * checking something ELSE - likely a separate flag in kernel data. */

  fprintf(fp, "\n  --- Searching kernel data for device type variable ---\n");

  /* Scan a range around SECURITY_FLAGS for related variables.
   * These flags are typically stored together. */
  intptr_t sf_addr = KERNEL_ADDRESS_SECURITY_FLAGS;
  intptr_t tid_addr = KERNEL_ADDRESS_TARGETID;
  fprintf(fp, "  SECURITY_FLAGS @ 0x%lx = 0x%02x\n",
          (unsigned long)sf_addr, kernel_getchar(sf_addr));
  fprintf(fp, "  TARGETID @ 0x%lx = 0x%02x\n",
          (unsigned long)tid_addr, kernel_getchar(tid_addr));

  /* Dump memory around these addresses to find the device type variable */
  if(sf_addr) {
    intptr_t scan_start = sf_addr - 256;
    unsigned char buf[1024];
    kernel_copyout(scan_start, buf, sizeof(buf));

    fprintf(fp, "\n  Memory around SECURITY_FLAGS (0x%lx-256 to +768):\n",
            (unsigned long)sf_addr);
    for(int i = 0; i < 1024; i += 16) {
      fprintf(fp, "    0x%lx: ", (unsigned long)(scan_start + i));
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

  /* Now let's try a direct approach: scan kernel text for
   * sceKernelIsDevKit's syscall entry.
   *
   * On FreeBSD, syscalls are dispatched via a sysent table.
   * sceKernelIsDevKit is syscall 616 (0x268) on PS5.
   *
   * But an easier approach: scan for the actual check pattern.
   * Since TARGETID=0x82 and IsDevKit()=0, the function must
   * check something OTHER than targetid. Let's find it by scanning
   * kernel text for a small function that returns 0 near code
   * that references TARGETID or SECURITY_FLAGS addresses. */

  /* Try brute force: scan kernel text for "xor eax,eax; ret" (31 c0 c3)
   * patterns and try patching each one, checking if IsDevKit changes */
  fprintf(fp, "\n  --- Trying to find sceKernelIsDevKit in kernel text ---\n");

  /* Read 16MB of kernel text in chunks */
  size_t chunk_size = 256 * 1024;
  unsigned char *chunk = malloc(chunk_size);
  if(!chunk) {
    fprintf(fp, "  ERROR: malloc failed\n");
    return;
  }

  /* Look for patterns that reference SECURITY_FLAGS or TARGETID
   * followed by a comparison and return 0 */
  int candidates_found = 0;

  for(size_t off = 0; off < 32 * 1024 * 1024; off += chunk_size) {
    int err = kernel_copyout(ktext + off, chunk, chunk_size);
    if(err) break;

    for(size_t i = 0; i < chunk_size - 16; i++) {
      /* Pattern 1: "xor eax,eax; ret" standalone (31 c0 c3)
       * preceded by some comparison */

      /* Pattern 2: Look for LEA/MOV that loads an address near
       * SECURITY_FLAGS, followed by test and return.
       *
       * More specifically, look for RIP-relative MOV that loads
       * from near SECURITY_FLAGS address */

      /* For now, let's try finding the function that contains
       * a reference to the TARGETID address.
       * RIP-relative addressing: the instruction encodes a 32-bit
       * signed offset from the NEXT instruction's address. */

      if(sf_addr) {
        /* Check for movzbl (%rip+disp32), %eax  = 0f b6 05 xx xx xx xx
         * where the displacement points to SECURITY_FLAGS */
        if(chunk[i] == 0x0f && chunk[i+1] == 0xb6 && chunk[i+2] == 0x05) {
          int32_t disp = *(int32_t *)&chunk[i+3];
          intptr_t target = (ktext + off + i + 7) + disp;
          if(target >= sf_addr - 32 && target <= sf_addr + 32) {
            fprintf(fp, "  Found SECURITY_FLAGS ref at kernel+0x%zx "
                    "(target=0x%lx)\n", off+i, (unsigned long)target);
            candidates_found++;

            /* Dump context around this instruction */
            size_t ctx_start = (i >= 32) ? i - 32 : 0;
            size_t ctx_end = (i + 64 < chunk_size) ? i + 64 : chunk_size;
            fprintf(fp, "    Context:\n");
            for(size_t ci = ctx_start; ci < ctx_end; ci += 16) {
              fprintf(fp, "    0x%lx: ",
                      (unsigned long)(ktext + off + ci));
              for(size_t cj = 0; cj < 16 && ci+cj < ctx_end; cj++)
                fprintf(fp, "%02x ", chunk[ci+cj]);
              fprintf(fp, "\n");
            }
          }
        }

        /* Also check for: movzbl (%rip+disp32), %eax  with other encodings
         * or mov (%rip+disp32), %al  = 8a 05 xx xx xx xx */
        if(chunk[i] == 0x8a && chunk[i+1] == 0x05) {
          int32_t disp = *(int32_t *)&chunk[i+2];
          intptr_t target = (ktext + off + i + 6) + disp;
          if(target >= sf_addr - 32 && target <= sf_addr + 32) {
            fprintf(fp, "  Found SECURITY_FLAGS ref (8a05) at kernel+0x%zx\n",
                    off+i);
            candidates_found++;
          }
        }

        /* Check for TARGETID references too */
        if(tid_addr && chunk[i] == 0x0f && chunk[i+1] == 0xb6 &&
           chunk[i+2] == 0x05) {
          int32_t disp = *(int32_t *)&chunk[i+3];
          intptr_t target = (ktext + off + i + 7) + disp;
          if(target >= tid_addr - 4 && target <= tid_addr + 4) {
            fprintf(fp, "  Found TARGETID ref at kernel+0x%zx "
                    "(target=0x%lx)\n", off+i, (unsigned long)target);
            candidates_found++;

            size_t ctx_start = (i >= 64) ? i - 64 : 0;
            size_t ctx_end = (i + 96 < chunk_size) ? i + 96 : chunk_size;
            fprintf(fp, "    Context:\n");
            for(size_t ci = ctx_start; ci < ctx_end; ci += 16) {
              fprintf(fp, "    0x%lx: ",
                      (unsigned long)(ktext + off + ci));
              for(size_t cj = 0; cj < 16 && ci+cj < ctx_end; cj++)
                fprintf(fp, "%02x ", chunk[ci+cj]);
              fprintf(fp, "\n");
            }
          }
        }
      }
    }

    if(candidates_found >= 50) break;
  }

  fprintf(fp, "  Total candidates: %d\n", candidates_found);
  free(chunk);

  /* After analysis: check again */
  fprintf(fp, "\n  After scan:\n");
  fprintf(fp, "    sceKernelIsDevKit()  = %d\n", sceKernelIsDevKit());
  fprintf(fp, "    sceKernelIsTestKit() = %d\n", sceKernelIsTestKit());
}

/* Phase 3: Try to call sceShellCoreUtilSetGnmCompositorOnScreenProfilerFlag
 * This function exists in SceShellCore (PID 58) and controls an on-screen
 * overlay. We can try to resolve it and call it via the shell core. */
static void
try_compositor_profiler(FILE *fp) {
  fprintf(fp, "\n=== COMPOSITOR ON-SCREEN PROFILER ===\n\n");

  pid_t shellcore_pid = find_process("SceShellCore");
  fprintf(fp, "  SceShellCore PID: %d\n", shellcore_pid);

  if(shellcore_pid < 0) {
    fprintf(fp, "  ERROR: SceShellCore not found\n");
    return;
  }

  /* Try to find sceShellCoreUtilSetGnmCompositorOnScreenProfilerFlag
   * in SceShellCore's loaded modules */
  const char *libs[] = {
    "libSceShellCoreUtil.sprx",
    "eboot.bin",
    NULL
  };

  for(int i = 0; libs[i]; i++) {
    uint32_t handle = 0;
    if(kernel_dynlib_handle(shellcore_pid, libs[i], &handle))
      continue;

    fprintf(fp, "  %s in SceShellCore: handle=0x%x\n", libs[i], handle);

    intptr_t base = kernel_dynlib_mapbase_addr(shellcore_pid, handle);
    fprintf(fp, "    base=0x%lx\n", (unsigned long)base);

    /* Try to find the function by symbol name */
    const char *syms[] = {
      "sceShellCoreUtilSetGnmCompositorOnScreenProfilerFlag",
      "sceShellCoreUtilGetGnmCompositorOnScreenProfilerFlag",
      "sceShellCoreUtilSetSystemNotifyFlag",
      "sceShellCoreUtilGetCdlgEnabledFreeze",
      NULL
    };

    for(int s = 0; syms[s]; s++) {
      intptr_t addr = kernel_dynlib_dlsym(shellcore_pid, handle, syms[s]);
      if(addr)
        fprintf(fp, "    %s = 0x%lx\n", syms[s], (unsigned long)addr);
    }
  }

  /* Scan SceShellCore memory for the string to find function address */
  fprintf(fp, "\n  Scanning SceShellCore for profiler flag string...\n");
  uint32_t eboot_handle = 0;
  if(!kernel_dynlib_handle(shellcore_pid, "eboot.bin", &eboot_handle)) {
    intptr_t base = kernel_dynlib_mapbase_addr(shellcore_pid, eboot_handle);
    if(base) {
      size_t chunk_sz = 256 * 1024;
      unsigned char *buf = malloc(chunk_sz);
      if(buf) {
        const char *needle = "sceShellCoreUtilSetGnmCompositorOnScreenProfilerFlag";
        size_t nlen = strlen(needle);

        for(size_t off = 0; off < 32 * 1024 * 1024; off += chunk_sz) {
          if(kernel_proc_copyout(shellcore_pid, base + off, buf, chunk_sz))
            break;

          int all_zero = 1;
          for(size_t c = 0; c < 256; c++) {
            if(buf[c]) { all_zero = 0; break; }
          }
          if(all_zero) break;

          for(size_t j = 0; j + nlen <= chunk_sz; j++) {
            if(!memcmp(&buf[j], needle, nlen)) {
              fprintf(fp, "    Found \"%s\" at 0x%lx\n",
                      needle, (unsigned long)(base + off + j));
            }
          }
        }
        free(buf);
      }
    }
  }
}

/* Phase 4: Try to directly patch the device type check in SceShellUI
 *
 * UpdateCheckDoCheckSystemForDevKitNative is at ~0x4ef990dd in eboot.bin
 * eboot.bin base = 0x4e05c000
 * So the string is at offset 0xf990dd - 0x5c000 = 0xF3D0DD from base
 * Actually: 0x4ef990dd - 0x4e05c000 = 0x09F3D0DD... that's huge.
 *
 * Wait: eboot.bin base=0x4e05c000, string at 0x4ef990dd.
 * Offset = 0x4ef990dd - 0x4e05c000 = 0x0F9D0DD
 * This is in the .rodata section of eboot.bin.
 *
 * The code that references this string likely calls sceKernelIsDevKit()
 * and branches based on the result. If we can find that branch and
 * NOP it (or flip the condition), the shell will think it's a devkit. */
static void
try_patch_shellui(FILE *fp) {
  fprintf(fp, "\n=== SHELLUI DEVKIT CHECK PATCH ===\n\n");

  pid_t shellui_pid = find_process("SceShellUI");
  fprintf(fp, "  SceShellUI PID: %d\n", shellui_pid);
  if(shellui_pid < 0) return;

  uint32_t eboot_handle = 0;
  if(kernel_dynlib_handle(shellui_pid, "eboot.bin", &eboot_handle)) {
    fprintf(fp, "  ERROR: can't get eboot handle\n");
    return;
  }

  intptr_t base = kernel_dynlib_mapbase_addr(shellui_pid, eboot_handle);
  fprintf(fp, "  eboot.bin base: 0x%lx\n", (unsigned long)base);

  /* The string "UpdateCheckDoCheckSystemForDevKitNative" is at 0x4ef990dd.
   * The code that calls sceKernelIsDevKit() should be nearby in .text.
   *
   * First, let's find sceKernelIsDevKit import in SceShellUI.
   * It's imported from libkernel_sys.sprx. */
  uint32_t libkernel_handle = 0;
  if(!kernel_dynlib_handle(shellui_pid, "libkernel_sys.sprx", &libkernel_handle)) {
    fprintf(fp, "  libkernel_sys.sprx handle=0x%x\n", libkernel_handle);

    /* Try to resolve sceKernelIsDevKit symbol address in the process */
    intptr_t isdevkit_addr = kernel_dynlib_dlsym(shellui_pid, libkernel_handle,
                                                  "sceKernelIsDevKit");
    intptr_t istestkit_addr = kernel_dynlib_dlsym(shellui_pid, libkernel_handle,
                                                   "sceKernelIsTestKit");
    intptr_t iscex_addr = kernel_dynlib_dlsym(shellui_pid, libkernel_handle,
                                               "sceKernelIsCEX");

    fprintf(fp, "    sceKernelIsDevKit  @ 0x%lx\n", (unsigned long)isdevkit_addr);
    fprintf(fp, "    sceKernelIsTestKit @ 0x%lx\n", (unsigned long)istestkit_addr);
    fprintf(fp, "    sceKernelIsCEX     @ 0x%lx\n", (unsigned long)iscex_addr);

    /* If we have the address, we can patch the function in the process.
     * Instead of patching in kernel, patch the userspace stub that wraps
     * the syscall. Make it return 1 instead of calling the syscall.
     *
     * x86_64:  mov eax, 1; ret  = b8 01 00 00 00 c3 */
    if(isdevkit_addr) {
      /* Read original bytes */
      unsigned char orig[16];
      kernel_proc_copyout(shellui_pid, isdevkit_addr, orig, 16);
      fprintf(fp, "    Original sceKernelIsDevKit code: ");
      for(int j = 0; j < 16; j++) fprintf(fp, "%02x ", orig[j]);
      fprintf(fp, "\n");

      /* Make the page writable */
      int old_prot = kernel_get_vmem_protection(shellui_pid, isdevkit_addr, 16);
      fprintf(fp, "    Page protection: 0x%x\n", old_prot);
      int mpret = kernel_set_vmem_protection(shellui_pid, isdevkit_addr, 4096, 7);
      fprintf(fp, "    mprotect(rwx): %d\n", mpret);

      if(mpret == 0 || old_prot >= 0) {
        /* Patch: mov eax, 1; ret */
        unsigned char patch[] = { 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3 };
        int pret = kernel_proc_copyin(shellui_pid, patch, isdevkit_addr, 6);
        fprintf(fp, "    Patch sceKernelIsDevKit -> return 1: %d\n", pret);

        /* Verify */
        unsigned char verify[16];
        kernel_proc_copyout(shellui_pid, isdevkit_addr, verify, 16);
        fprintf(fp, "    After patch: ");
        for(int j = 0; j < 16; j++) fprintf(fp, "%02x ", verify[j]);
        fprintf(fp, "\n");
      }
    }

    /* Also patch sceKernelIsTestKit to return 1 */
    if(istestkit_addr) {
      unsigned char orig[16];
      kernel_proc_copyout(shellui_pid, istestkit_addr, orig, 16);
      fprintf(fp, "\n    Original sceKernelIsTestKit code: ");
      for(int j = 0; j < 16; j++) fprintf(fp, "%02x ", orig[j]);
      fprintf(fp, "\n");

      kernel_set_vmem_protection(shellui_pid, istestkit_addr, 4096, 7);
      unsigned char patch[] = { 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3 };
      int pret = kernel_proc_copyin(shellui_pid, patch, istestkit_addr, 6);
      fprintf(fp, "    Patch sceKernelIsTestKit -> return 1: %d\n", pret);
    }

    /* Also patch sceKernelIsCEX to return 0 (devkits are not CEX) */
    if(iscex_addr) {
      unsigned char orig[16];
      kernel_proc_copyout(shellui_pid, iscex_addr, orig, 16);
      fprintf(fp, "\n    Original sceKernelIsCEX code: ");
      for(int j = 0; j < 16; j++) fprintf(fp, "%02x ", orig[j]);
      fprintf(fp, "\n");

      kernel_set_vmem_protection(shellui_pid, iscex_addr, 4096, 7);
      unsigned char patch[] = { 0x31, 0xc0, 0xc3 }; /* xor eax,eax; ret */
      int pret = kernel_proc_copyin(shellui_pid, patch, iscex_addr, 3);
      fprintf(fp, "    Patch sceKernelIsCEX -> return 0: %d\n", pret);
    }
  }

  /* Also need to patch SceShellCore (PID 58) since it may check too */
  pid_t shellcore_pid = find_process("SceShellCore");
  fprintf(fp, "\n  SceShellCore PID: %d\n", shellcore_pid);
  if(shellcore_pid > 0) {
    uint32_t lk_handle = 0;
    if(!kernel_dynlib_handle(shellcore_pid, "libkernel_sys.sprx", &lk_handle)) {
      intptr_t isdevkit_addr = kernel_dynlib_dlsym(shellcore_pid, lk_handle,
                                                    "sceKernelIsDevKit");
      intptr_t istestkit_addr = kernel_dynlib_dlsym(shellcore_pid, lk_handle,
                                                     "sceKernelIsTestKit");

      fprintf(fp, "    sceKernelIsDevKit  @ 0x%lx\n", (unsigned long)isdevkit_addr);
      fprintf(fp, "    sceKernelIsTestKit @ 0x%lx\n", (unsigned long)istestkit_addr);

      if(isdevkit_addr) {
        kernel_set_vmem_protection(shellcore_pid, isdevkit_addr, 4096, 7);
        unsigned char patch[] = { 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3 };
        int pret = kernel_proc_copyin(shellcore_pid, patch, isdevkit_addr, 6);
        fprintf(fp, "    Patch SceShellCore sceKernelIsDevKit -> return 1: %d\n", pret);
      }
      if(istestkit_addr) {
        kernel_set_vmem_protection(shellcore_pid, istestkit_addr, 4096, 7);
        unsigned char patch[] = { 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3 };
        int pret = kernel_proc_copyin(shellcore_pid, patch, istestkit_addr, 6);
        fprintf(fp, "    Patch SceShellCore sceKernelIsTestKit -> return 1: %d\n", pret);
      }
    }
  }
}

int
main(void) {
  mkdir(OUT_DIR, 0777);
  elevate();
  notify("dipswpatch: starting...");
  printf("dipswpatch: elevated\n");

  FILE *fp;
  char path[256];
  snprintf(path, sizeof(path), "%s/dipswpatch.txt", OUT_DIR);
  fp = fopen(path, "w");
  if(!fp) { perror(path); return 1; }

  /* Check pre-patch state */
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

  /* Phase 2: Scan kernel for sceKernelIsDevKit */
  patch_kernel_isdevkit(fp);

  /* Phase 3: Patch SceShellUI and SceShellCore in-process */
  try_patch_shellui(fp);

  /* Phase 4: Try compositor profiler */
  try_compositor_profiler(fp);

  /* Check post-patch state from OUR process */
  fprintf(fp, "\n=== POST-PATCH STATE (from payload process) ===\n");
  fprintf(fp, "  sceKernelIsDevKit()  = %d\n", sceKernelIsDevKit());
  fprintf(fp, "  sceKernelIsTestKit() = %d\n", sceKernelIsTestKit());
  fprintf(fp, "  sceKernelIsCEX()     = %d\n", sceKernelIsCEX());

  fprintf(fp, "\n=== INSTRUCTIONS ===\n");
  fprintf(fp, "If patches succeeded, SceShellUI needs to be restarted\n");
  fprintf(fp, "to re-evaluate the devkit checks.\n");
  fprintf(fp, "Run killshell.elf to restart it, or reboot.\n");
  fprintf(fp, "The patches are in userspace stubs, so SceShellUI needs\n");
  fprintf(fp, "to be patched AFTER it restarts (it gets a fresh copy).\n");
  fprintf(fp, "\nAlternative: We need to patch the KERNEL syscall handler\n");
  fprintf(fp, "instead, so ALL processes see IsDevKit()=1.\n");

  fclose(fp);
  printf("dipswpatch: wrote %s\n", path);
  notify("dipswpatch: done - check results");
  printf("dipswpatch: done\n");
  return 0;
}
