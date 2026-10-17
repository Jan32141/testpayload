/* panelscan: Reverse-engineer the devkit panel enable check.
 * Scans SceShellUI process memory for:
 * 1. libSceDipsw.sprx full code dump (find real ioctl encoding)
 * 2. Code near "UpdateCheckDoCheckSystemForDevKitNative" string
 * 3. Code near "DevKit/TestKit successfully Activated" string
 * 4. Code near QSP functions
 * 5. machdep.check_genuine_devkit_for_psm sysctl
 * 6. libSceDipsw symbol table scan
 *
 * SAFETY: Read-only scan, no patching. NEVER touches IDU mode. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysctl.h>

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

/* Hex dump helper */
static void
hexdump(FILE *fp, const unsigned char *buf, size_t len,
        intptr_t base_addr, const char *label) {
  fprintf(fp, "\n  --- %s ---\n", label);
  for(size_t i = 0; i < len; i += 16) {
    fprintf(fp, "  0x%lx: ", (unsigned long)(base_addr + i));
    for(size_t j = 0; j < 16 && i+j < len; j++)
      fprintf(fp, "%02x ", buf[i+j]);
    for(size_t j = (len - i < 16 ? len - i : 16); j < 16; j++)
      fprintf(fp, "   ");
    fprintf(fp, " ");
    for(size_t j = 0; j < 16 && i+j < len; j++) {
      unsigned char c = buf[i+j];
      fprintf(fp, "%c", (c >= 0x20 && c < 0x7f) ? c : '.');
    }
    fprintf(fp, "\n");
  }
}

/* Phase 1: Dump libSceDipsw.sprx code from SceShellUI */
static void
dump_dipsw_lib(FILE *fp, pid_t pid) {
  fprintf(fp, "=== LIBSCEDIPSW CODE DUMP ===\n");

  uint32_t handle = 0;
  if(kernel_dynlib_handle(pid, "libSceDipsw.sprx", &handle)) {
    fprintf(fp, "  libSceDipsw.sprx not found in SceShellUI\n");
    return;
  }

  intptr_t base = kernel_dynlib_mapbase_addr(pid, handle);
  intptr_t entry = kernel_dynlib_entry_addr(pid, handle);
  fprintf(fp, "  handle=0x%x base=0x%lx entry=0x%lx\n",
          handle, (unsigned long)base, (unsigned long)entry);

  if(!base) return;

  /* Try to resolve known dipsw symbols */
  const char *syms[] = {
    "sceDipswIsDevKit",
    "sceDipswIsTestKit",
    "sceDipswIsCEX",
    "sceDipswIsDex",
    "sceDipswGetValue",
    "sceDipswGetFlag",
    "sceDipswSetFlag",
    "sceDipswClearFlag",
    "sceDipswInit",
    "sceDipswCheckDipsw",
    "sceDipswGetHwConfig",
    "sceDipswReadData",
    "sceDipswGetData",
    "sceDipswDipswCheck",
    "sceDipswGetDeviceType",
    "_sceDipswIoctl",
    "sceDipswOpen",
    NULL
  };

  fprintf(fp, "\n  Symbol resolution:\n");
  for(int i = 0; syms[i]; i++) {
    intptr_t addr = kernel_dynlib_dlsym(pid, handle, syms[i]);
    if(addr)
      fprintf(fp, "    %s = 0x%lx (offset +0x%lx)\n",
              syms[i], (unsigned long)addr, (unsigned long)(addr - base));
  }

  /* Dump first 8KB of library code — should contain all exported functions */
  size_t dump_sz = 8192;
  unsigned char *buf = malloc(dump_sz);
  if(!buf) return;

  if(!kernel_proc_copyout(pid, base, buf, dump_sz)) {
    hexdump(fp, buf, dump_sz, base, "libSceDipsw first 8KB");

    /* Scan for ioctl-related patterns in the code:
     * syscall instruction = 0f 05
     * int 0x80 = cd 80
     * Also look for /dev/dipsw string reference */
    fprintf(fp, "\n  Scanning for syscall instructions (0f 05):\n");
    for(size_t i = 0; i + 1 < dump_sz; i++) {
      if(buf[i] == 0x0f && buf[i+1] == 0x05) {
        fprintf(fp, "    syscall at base+0x%zx (0x%lx)\n",
                i, (unsigned long)(base + i));
        /* Show context: 32 bytes before, 16 after */
        size_t ctx_start = (i >= 32) ? i - 32 : 0;
        size_t ctx_end = (i + 16 < dump_sz) ? i + 16 : dump_sz;
        for(size_t ci = ctx_start; ci < ctx_end; ci += 16) {
          fprintf(fp, "      0x%lx: ", (unsigned long)(base + ci));
          for(size_t cj = 0; cj < 16 && ci+cj < ctx_end; cj++)
            fprintf(fp, "%02x ", buf[ci+cj]);
          fprintf(fp, "\n");
        }
      }
    }

    /* Look for ioctl command constants — typically loaded as immediate
     * values via MOV into registers. The _IOR('d',n,uint32_t) encoding
     * for 'd' = 0x64:
     *   _IOR = direction=IOC_OUT=0x40000000, size=4<<16=0x40000, group='d'<<8=0x6400
     *   So _IOR('d', 0, uint32_t) = 0x40046400
     *   _IOR('d', 1, uint32_t) = 0x40046401
     * But the PS5 might use different encoding.
     * Look for 0x6400-0x64ff or 0x40046400-0x400464ff patterns */
    fprintf(fp, "\n  Scanning for potential ioctl constants:\n");
    for(size_t i = 0; i + 3 < dump_sz; i++) {
      uint32_t val = *(uint32_t *)&buf[i];
      /* Check for _IOR('d', idx, uint32_t) = 0x400464xx */
      if((val & 0xFFFFFF00) == 0x40046400) {
        fprintf(fp, "    Found 0x%08x at base+0x%zx (_IOR('d',%d,u32))\n",
                val, i, val & 0xFF);
      }
      /* Check for _IOW('d', idx, uint32_t) = 0x800464xx */
      if((val & 0xFFFFFF00) == 0x80046400) {
        fprintf(fp, "    Found 0x%08x at base+0x%zx (_IOW('d',%d,u32))\n",
                val, i, val & 0xFF);
      }
      /* Check for plain 'd' << 8 patterns */
      if((val & 0x0000FF00) == 0x00006400 && (val & 0xFFFF0000) != 0 &&
         val != 0x40046400 && i > 0 &&
         (buf[i-1] == 0xbe || buf[i-1] == 0xb9 || buf[i-1] == 0xba ||
          buf[i-1] == 0xbf)) {
        fprintf(fp, "    Found 0x%08x at base+0x%zx (has 'd'<<8)\n", val, i);
      }
    }
  }

  free(buf);
}

/* Phase 2: Find code around key strings in SceShellUI eboot */
static void
scan_eboot_strings(FILE *fp, pid_t pid) {
  fprintf(fp, "\n=== EBOOT STRING CROSS-REFERENCE ===\n");

  uint32_t eboot_handle = 0;
  if(kernel_dynlib_handle(pid, "eboot.bin", &eboot_handle)) {
    fprintf(fp, "  ERROR: can't get eboot handle\n");
    return;
  }

  intptr_t base = kernel_dynlib_mapbase_addr(pid, eboot_handle);
  fprintf(fp, "  eboot.bin base=0x%lx\n", (unsigned long)base);
  if(!base) return;

  /* Strings to find and dump context around */
  const char *targets[] = {
    "UpdateCheckDoCheckSystemForDevKitNative",
    "DevKit/TestKit successfully Activated",
    "DevKit/TestKit expires in",
    "This DevKit/TestKit is expired",
    "QSP_set_host_system_info",
    "QSP_get_device_ip_address",
    "QSP_get_device_key_label",
    "check_genuine_devkit_for_psm",
    "devkit_panel",
    "DevKitPanel",
    "host_overlay",
    "overlayPosition",
    "dipsw",
    "IsDevKit",
    "isDevKit",
    "is_devkit",
    NULL
  };

  size_t chunk_sz = 256 * 1024;
  unsigned char *buf = malloc(chunk_sz);
  if(!buf) return;

  /* First pass: find all string locations */
  typedef struct { const char *str; intptr_t addr; } hit_t;
  hit_t hits[256];
  int nhits = 0;

  fprintf(fp, "\n  Scanning for target strings...\n");

  for(size_t off = 0; off < 16UL * 1024 * 1024 && nhits < 256; off += chunk_sz) {
    if(kernel_proc_copyout(pid, base + off, buf, chunk_sz))
      break;

    /* Check for end of mapped region */
    int all_zero = 1;
    for(size_t c = 0; c < 256; c++) {
      if(buf[c]) { all_zero = 0; break; }
    }
    if(all_zero) break;

    for(int t = 0; targets[t] && nhits < 256; t++) {
      size_t tlen = strlen(targets[t]);
      for(size_t j = 0; j + tlen <= chunk_sz && nhits < 256; j++) {
        if(!memcmp(&buf[j], targets[t], tlen)) {
          intptr_t addr = base + off + j;
          fprintf(fp, "    \"%s\" at 0x%lx (eboot+0x%lx)\n",
                  targets[t], (unsigned long)addr,
                  (unsigned long)(addr - base));
          hits[nhits].str = targets[t];
          hits[nhits].addr = addr;
          nhits++;
        }
      }
    }
  }

  fprintf(fp, "  Found %d string hits\n", nhits);

  /* Second pass: for each important string, dump 256 bytes of context
   * around it AND search for code that references it via RIP-relative LEA.
   *
   * A LEA rdi,[rip+disp32] instruction that points to the string address
   * tells us where the calling code is. */

  fprintf(fp, "\n  === String context dumps ===\n");

  for(int h = 0; h < nhits; h++) {
    intptr_t str_addr = hits[h].addr;

    /* Dump 128 bytes around the string */
    unsigned char ctx[256];
    intptr_t ctx_start = str_addr - 64;
    if(!kernel_proc_copyout(pid, ctx_start, ctx, 256)) {
      char label[256];
      snprintf(label, sizeof(label), "Context around \"%s\"", hits[h].str);
      hexdump(fp, ctx, 256, ctx_start, label);
    }
  }

  /* Third pass: scan .text section for LEA instructions that reference
   * the found strings. The .text is typically at the start of eboot,
   * .rodata after it. We scan the first 8MB (likely all .text). */
  fprintf(fp, "\n  === Code cross-references ===\n");

  for(size_t off = 0; off < 8UL * 1024 * 1024; off += chunk_sz) {
    if(kernel_proc_copyout(pid, base + off, buf, chunk_sz))
      break;

    /* Check for all-zero (past end of .text) */
    int has_code = 0;
    for(size_t c = 0; c < chunk_sz; c += 4096) {
      if(buf[c] != 0 || buf[c+1] != 0) { has_code = 1; break; }
    }
    if(!has_code) continue;

    for(size_t i = 0; i + 7 < chunk_sz; i++) {
      /* LEA reg, [rip+disp32]:
       * 48 8d 3d xx xx xx xx  = lea rdi,[rip+xx]  (arg1)
       * 48 8d 35 xx xx xx xx  = lea rsi,[rip+xx]  (arg2)
       * 48 8d 05 xx xx xx xx  = lea rax,[rip+xx]
       * 48 8d 0d xx xx xx xx  = lea rcx,[rip+xx]
       * 48 8d 15 xx xx xx xx  = lea rdx,[rip+xx] */
      if(buf[i] == 0x48 && buf[i+1] == 0x8d &&
         (buf[i+2] == 0x3d || buf[i+2] == 0x35 || buf[i+2] == 0x05 ||
          buf[i+2] == 0x0d || buf[i+2] == 0x15)) {
        int32_t disp = *(int32_t *)&buf[i+3];
        intptr_t target = (base + off + i + 7) + disp;

        for(int h = 0; h < nhits; h++) {
          if(target == hits[h].addr) {
            intptr_t code_addr = base + off + i;
            fprintf(fp, "\n  XREF: code at 0x%lx (eboot+0x%lx) references "
                    "\"%s\"\n",
                    (unsigned long)code_addr,
                    (unsigned long)(code_addr - base),
                    hits[h].str);

            /* Dump 128 bytes around the referencing code */
            size_t ctx_start = (i >= 64) ? i - 64 : 0;
            size_t ctx_end = (i + 128 < chunk_sz) ? i + 128 : chunk_sz;
            unsigned char *code_ctx = &buf[ctx_start];
            size_t code_len = ctx_end - ctx_start;
            hexdump(fp, code_ctx, code_len, base + off + ctx_start,
                    "Code context");
          }
        }
      }

      /* Also check without REX prefix for 32-bit LEA:
       * 8d 3d xx xx xx xx  = lea edi,[rip+xx] */
      if(buf[i] == 0x8d &&
         (buf[i+1] == 0x3d || buf[i+1] == 0x35 || buf[i+1] == 0x05 ||
          buf[i+1] == 0x0d || buf[i+1] == 0x15) &&
         i + 6 < chunk_sz) {
        int32_t disp = *(int32_t *)&buf[i+2];
        intptr_t target = (base + off + i + 6) + disp;

        for(int h = 0; h < nhits; h++) {
          if(target == hits[h].addr) {
            intptr_t code_addr = base + off + i;
            fprintf(fp, "\n  XREF(32): code at 0x%lx (eboot+0x%lx) references "
                    "\"%s\"\n",
                    (unsigned long)code_addr,
                    (unsigned long)(code_addr - base),
                    hits[h].str);

            size_t ctx_start = (i >= 64) ? i - 64 : 0;
            size_t ctx_end = (i + 128 < chunk_sz) ? i + 128 : chunk_sz;
            hexdump(fp, &buf[ctx_start], ctx_end - ctx_start,
                    base + off + ctx_start, "Code context");
          }
        }
      }
    }
  }

  free(buf);
}

/* Phase 3: Try machdep.check_genuine_devkit_for_psm sysctl */
static void
try_sysctl_checks(FILE *fp) {
  fprintf(fp, "\n=== SYSCTL DEVKIT CHECKS ===\n");

  /* Try various machdep sysctls related to devkit */
  const char *sysctls[] = {
    "machdep.check_genuine_devkit_for_psm",
    "machdep.devkit_type",
    "machdep.dipsw",
    "machdep.targetid",
    "kern.sched.cpusetsize",
    "security.mac.allow_devkit",
    "hw.machine",
    "kern.ostype",
    "kern.osrelease",
    "kern.version",
    NULL
  };

  for(int i = 0; sysctls[i]; i++) {
    char buf[256] = {0};
    size_t len = sizeof(buf);
    int err = sysctlbyname(sysctls[i], buf, &len, NULL, 0);
    if(!err) {
      /* Try to print as int if small, else as string */
      if(len <= 4) {
        int val = 0;
        memcpy(&val, buf, len);
        fprintf(fp, "  %s = %d (0x%x) [%zu bytes]\n",
                sysctls[i], val, val, len);
      } else {
        /* Check if it's printable */
        int printable = 1;
        for(size_t j = 0; j < len - 1; j++) {
          if(buf[j] < 0x20 || buf[j] > 0x7e) { printable = 0; break; }
        }
        if(printable)
          fprintf(fp, "  %s = \"%s\" [%zu bytes]\n", sysctls[i], buf, len);
        else {
          fprintf(fp, "  %s = [%zu bytes]: ", sysctls[i], len);
          for(size_t j = 0; j < len && j < 32; j++)
            fprintf(fp, "%02x ", (unsigned char)buf[j]);
          fprintf(fp, "\n");
        }
      }
    } else {
      fprintf(fp, "  %s = error %d\n", sysctls[i], err);
    }
  }

  /* Try to enumerate machdep children */
  fprintf(fp, "\n  Trying machdep MIB enumeration:\n");
  int mib[2] = { CTL_MACHDEP, 0 };
  for(int i = 0; i < 32; i++) {
    mib[1] = i;
    char buf[256] = {0};
    size_t len = sizeof(buf);
    int err = sysctl(mib, 2, buf, &len, NULL, 0);
    if(!err && len > 0) {
      fprintf(fp, "    machdep.%d = [%zu bytes]: ", i, len);
      if(len <= 4) {
        int val = 0; memcpy(&val, buf, len);
        fprintf(fp, "%d (0x%x)\n", val, val);
      } else {
        for(size_t j = 0; j < len && j < 16; j++)
          fprintf(fp, "%02x ", (unsigned char)buf[j]);
        fprintf(fp, "\n");
      }
    }
  }
}

/* Phase 4: Scan SceShellUI's libSceDipsw for /dev/dipsw string
 * and the code around it to understand the ioctl interface */
static void
scan_dipsw_in_heap(FILE *fp, pid_t pid) {
  fprintf(fp, "\n=== DIPSW REFERENCES IN SHELLUI MODULES ===\n");

  /* We know from deepscan that /dev/dipsw string was at 0x80391023c
   * and SCE_SYSMODULE_INTERNAL_DIPSW at 0x801c91e5e.
   * libSceDipsw base was 0x80390c000 in the previous run.
   * Let's check the current addresses. */

  uint32_t dipsw_handle = 0;
  if(kernel_dynlib_handle(pid, "libSceDipsw.sprx", &dipsw_handle)) {
    fprintf(fp, "  libSceDipsw not loaded\n");
    return;
  }

  intptr_t dbase = kernel_dynlib_mapbase_addr(pid, dipsw_handle);
  fprintf(fp, "  libSceDipsw base=0x%lx\n", (unsigned long)dbase);

  /* Scan the library for the /dev/dipsw string to find it precisely */
  size_t lib_sz = 64 * 1024; /* dipsw lib is small */
  unsigned char *buf = malloc(lib_sz);
  if(!buf) return;

  if(kernel_proc_copyout(pid, dbase, buf, lib_sz)) {
    fprintf(fp, "  Failed to read libSceDipsw\n");
    free(buf);
    return;
  }

  /* Find /dev/dipsw string */
  const char *dipsw_str = "/dev/dipsw";
  size_t dlen = strlen(dipsw_str);
  for(size_t i = 0; i + dlen < lib_sz; i++) {
    if(!memcmp(&buf[i], dipsw_str, dlen)) {
      fprintf(fp, "  \"/dev/dipsw\" at base+0x%zx (0x%lx)\n",
              i, (unsigned long)(dbase + i));
    }
  }

  /* Find the format string for dipsw errors */
  const char *fmt_str = "dipsw [0x%02x]";
  size_t flen = strlen(fmt_str);
  for(size_t i = 0; i + flen < lib_sz; i++) {
    if(!memcmp(&buf[i], fmt_str, flen)) {
      fprintf(fp, "  dipsw error format at base+0x%zx (0x%lx)\n",
              i, (unsigned long)(dbase + i));

      /* Dump the full format string */
      fprintf(fp, "    Full string: \"");
      for(size_t j = i; j < lib_sz && buf[j]; j++)
        fprintf(fp, "%c", (buf[j] >= 0x20 && buf[j] < 0x7f) ? buf[j] : '?');
      fprintf(fp, "\"\n");
    }
  }

  /* Scan for all printable strings in the library */
  fprintf(fp, "\n  All strings in libSceDipsw:\n");
  for(size_t i = 0; i < lib_sz; i++) {
    if(buf[i] >= 0x20 && buf[i] < 0x7f) {
      size_t start = i;
      while(i < lib_sz && buf[i] >= 0x20 && buf[i] < 0x7f) i++;
      if(i - start >= 4 && buf[i] == 0) {
        fprintf(fp, "    base+0x%zx: \"", start);
        for(size_t j = start; j < i; j++) fprintf(fp, "%c", buf[j]);
        fprintf(fp, "\"\n");
      }
    }
  }

  /* Now look for all ioctl-like constants in the code section.
   * The ioctl number encoding on FreeBSD:
   *   bits 31-30: direction (00=none, 01=out, 10=in, 11=inout)
   *   Wait, actually FreeBSD uses:
   *   bits 31: IOC_IN (0x80000000)  = write
   *   bits 30: IOC_OUT (0x40000000) = read
   *   bits 29-16: size
   *   bits 15-8: group
   *   bits 7-0: number
   *
   *   For /dev/dipsw with group 'd' = 0x64:
   *   _IOR('d', n, type) = IOC_OUT | (sizeof(type)<<16) | ('d'<<8) | n
   *
   * But PS5 might use a completely different scheme.
   * Let's look for any 4-byte constant with 'd' (0x64) in byte position 1 */

  fprintf(fp, "\n  Scanning code for ioctl-related constants:\n");
  for(size_t i = 0; i + 4 < lib_sz; i++) {
    uint32_t val = *(uint32_t *)&buf[i];

    /* Standard FreeBSD _IOR('d', n, uint32_t) */
    if((val & 0xFFFFFF00) == 0x40046400)
      fprintf(fp, "    0x%08x at +0x%zx: _IOR('d',%d,u32)\n", val, i, val & 0xFF);

    /* _IOW('d', n, uint32_t) */
    if((val & 0xFFFFFF00) == 0x80046400)
      fprintf(fp, "    0x%08x at +0x%zx: _IOW('d',%d,u32)\n", val, i, val & 0xFF);

    /* _IOWR('d', n, uint32_t) */
    if((val & 0xFFFFFF00) == 0xC0046400)
      fprintf(fp, "    0x%08x at +0x%zx: _IOWR('d',%d,u32)\n", val, i, val & 0xFF);

    /* _IO('d', n) = no data, just command */
    if((val & 0xFFFF0000) == 0x20006400)
      fprintf(fp, "    0x%08x at +0x%zx: _IO('d',%d)\n", val, i, val & 0xFF);

    /* PS5 custom: maybe just 'd' << 8 + index, no size/direction */
    if(val >= 0x6400 && val <= 0x64FF &&
       (i == 0 || buf[i-1] == 0xbe || buf[i-1] == 0xb9 ||
        buf[i-1] == 0xba || buf[i-1] == 0xbf || buf[i-1] == 0xbb))
      fprintf(fp, "    0x%08x at +0x%zx: plain 'd'<<8+%d\n", val, i, val - 0x6400);

    /* Check for single byte 0x64 as immediate in MOV reg, imm8 context
     * for a small ioctl command */
  }

  free(buf);
}

/* Phase 5: Dump interesting SceShellCore library info */
static void
scan_shellcore_libs(FILE *fp) {
  fprintf(fp, "\n=== SCESHELLCORE LIBRARY INFO ===\n");

  pid_t pid = find_process("SceShellCore");
  if(pid < 0) {
    fprintf(fp, "  SceShellCore not found\n");
    return;
  }
  fprintf(fp, "  SceShellCore PID: %d\n", pid);

  /* Check for libSceDipsw in SceShellCore too */
  uint32_t dipsw_handle = 0;
  if(!kernel_dynlib_handle(pid, "libSceDipsw.sprx", &dipsw_handle)) {
    intptr_t base = kernel_dynlib_mapbase_addr(pid, dipsw_handle);
    fprintf(fp, "  libSceDipsw.sprx in ShellCore: handle=0x%x base=0x%lx\n",
            dipsw_handle, (unsigned long)base);
  } else {
    fprintf(fp, "  libSceDipsw.sprx NOT loaded in SceShellCore\n");
  }

  /* Try to resolve devkit-panel-related symbols in ShellCore eboot */
  uint32_t eboot_handle = 0;
  if(!kernel_dynlib_handle(pid, "eboot.bin", &eboot_handle)) {
    intptr_t base = kernel_dynlib_mapbase_addr(pid, eboot_handle);
    fprintf(fp, "  eboot.bin: handle=0x%x base=0x%lx\n",
            eboot_handle, (unsigned long)base);

    const char *syms[] = {
      "sceShellCoreUtilSetGnmCompositorOnScreenProfilerFlag",
      "sceShellCoreUtilGetGnmCompositorOnScreenProfilerFlag",
      "sceShellCoreUtilIsDevKit",
      "sceShellCoreUtilIsTestKit",
      "sceShellCoreUtilGetDevType",
      "sceShellCoreUtilSetDevKitPanel",
      "sceShellCoreUtilGetDevKitPanelInfo",
      NULL
    };
    for(int i = 0; syms[i]; i++) {
      intptr_t addr = kernel_dynlib_dlsym(pid, eboot_handle, syms[i]);
      if(addr)
        fprintf(fp, "    %s = 0x%lx\n", syms[i], (unsigned long)addr);
    }
  }

  /* Check what other interesting libs are loaded */
  const char *check_libs[] = {
    "libSceShellCoreUtil.sprx",
    "libSceSysmodule.sprx",
    "libSceSystemService.sprx",
    "libSceIpmi.sprx",
    NULL
  };
  for(int i = 0; check_libs[i]; i++) {
    uint32_t h = 0;
    if(!kernel_dynlib_handle(pid, check_libs[i], &h)) {
      intptr_t b = kernel_dynlib_mapbase_addr(pid, h);
      fprintf(fp, "  %s: handle=0x%x base=0x%lx\n",
              check_libs[i], h, (unsigned long)b);
    }
  }
}

int
main(void) {
  mkdir(OUT_DIR, 0777);
  elevate();
  notify("panelscan: starting...");
  printf("panelscan: elevated\n");

  char path[256];
  snprintf(path, sizeof(path), "%s/panelscan.txt", OUT_DIR);
  FILE *fp = fopen(path, "w");
  if(!fp) { perror(path); return 1; }

  fprintf(fp, "=== PANELSCAN: DEVKIT PANEL REVERSE ENGINEERING ===\n\n");
  fprintf(fp, "sceKernelIsDevKit()  = %d\n", sceKernelIsDevKit());
  fprintf(fp, "sceKernelIsTestKit() = %d\n", sceKernelIsTestKit());
  fprintf(fp, "sceKernelIsCEX()     = %d\n", sceKernelIsCEX());
  fprintf(fp, "SECURITY_FLAGS = 0x%02x\n",
          kernel_getchar(KERNEL_ADDRESS_SECURITY_FLAGS));
  fprintf(fp, "TARGETID = 0x%02x\n",
          kernel_getchar(KERNEL_ADDRESS_TARGETID));
  fprintf(fp, "\n");

  pid_t shellui_pid = find_process("SceShellUI");
  fprintf(fp, "SceShellUI PID: %d\n\n", shellui_pid);

  if(shellui_pid > 0) {
    /* Phase 1: libSceDipsw code dump */
    printf("panelscan: phase 1 - dipsw lib dump\n");
    dump_dipsw_lib(fp, shellui_pid);

    /* Phase 2: Eboot string xrefs */
    printf("panelscan: phase 2 - eboot string xrefs\n");
    notify("panelscan: scanning eboot strings...");
    scan_eboot_strings(fp, shellui_pid);

    /* Phase 4: dipsw in heap */
    printf("panelscan: phase 4 - dipsw heap scan\n");
    scan_dipsw_in_heap(fp, shellui_pid);
  }

  /* Phase 3: sysctl checks */
  printf("panelscan: phase 3 - sysctl checks\n");
  try_sysctl_checks(fp);

  /* Phase 5: ShellCore libs */
  printf("panelscan: phase 5 - shellcore libs\n");
  scan_shellcore_libs(fp);

  fclose(fp);
  printf("panelscan: wrote %s\n", path);
  notify("panelscan: done - check results");
  printf("panelscan: done\n");
  return 0;
}
