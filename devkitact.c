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

  /* Current value */
  int cur_val = -1;
  size_t len = sizeof(cur_val);
  int err = sysctlbyname("machdep.check_genuine_devkit_for_psm",
                          &cur_val, &len, NULL, 0);
  fprintf(fp, "  Current machdep.check_genuine_devkit_for_psm = %d "
          "(err=%d)\n", cur_val, err);

  if(err) {
    fprintf(fp, "  ERROR: sysctl not available\n");
    return;
  }

  /* Try to SET the sysctl directly (probably won't work without kernel priv) */
  int new_val = 1;
  err = sysctlbyname("machdep.check_genuine_devkit_for_psm",
                      NULL, NULL, &new_val, sizeof(new_val));
  fprintf(fp, "  Direct sysctl write attempt: err=%d errno=%d\n", err, errno);

  /* Check if it changed */
  cur_val = -1;
  len = sizeof(cur_val);
  sysctlbyname("machdep.check_genuine_devkit_for_psm", &cur_val, &len, NULL, 0);
  fprintf(fp, "  After direct write: value = %d\n", cur_val);

  if(cur_val == 1) {
    fprintf(fp, "  SUCCESS: sysctl patched via direct write!\n");
    return;
  }

  /* Direct write failed. Scan kernel data for the backing variable.
   * The string "check_genuine_devkit_for_psm" should be in kernel rodata.
   * We'll scan kernel data section to find it. */
  fprintf(fp, "\n  Scanning kernel data for sysctl string...\n");

  intptr_t kdata = KERNEL_ADDRESS_DATA_BASE;
  if(!kdata) {
    fprintf(fp, "  ERROR: kernel data base not available\n");
    return;
  }

  fprintf(fp, "  KERNEL_DATA_BASE = 0x%lx\n", (unsigned long)kdata);

  /* Scan kernel data/rodata for "check_genuine_devkit_for_psm" string */
  const char *needle = "check_genuine_devkit_for_psm";
  size_t nlen = strlen(needle);
  size_t chunk_sz = 256 * 1024;
  unsigned char *buf = malloc(chunk_sz);
  if(!buf) return;

  intptr_t string_addr = 0;

  /* Scan up to 64MB of kernel data */
  for(size_t off = 0; off < 64UL * 1024 * 1024; off += chunk_sz) {
    int ret = kernel_copyout(kdata + off, buf, chunk_sz);
    if(ret) {
      fprintf(fp, "  kernel_copyout at offset 0x%zx failed: %d\n", off, ret);
      break;
    }

    for(size_t i = 0; i + nlen < chunk_sz; i++) {
      if(!memcmp(&buf[i], needle, nlen) && buf[i + nlen] == 0) {
        string_addr = kdata + off + i;
        fprintf(fp, "  Found \"%s\" at 0x%lx (kdata+0x%lx)\n",
                needle, (unsigned long)string_addr,
                (unsigned long)(string_addr - kdata));

        /* Dump context around the string */
        size_t ctx_start = (i >= 64) ? i - 64 : 0;
        size_t ctx_end = (i + 128 < chunk_sz) ? i + 128 : chunk_sz;
        for(size_t ci = ctx_start; ci < ctx_end; ci += 16) {
          fprintf(fp, "    0x%lx: ", (unsigned long)(kdata + off + ci));
          for(size_t cj = 0; cj < 16 && ci+cj < ctx_end; cj++)
            fprintf(fp, "%02x ", buf[ci+cj]);
          fprintf(fp, "\n");
        }
        goto found_string;
      }
    }
  }

  fprintf(fp, "  String not found in kernel data (scanned 64MB)\n");
  free(buf);
  return;

found_string:
  /* Now scan kernel data for pointers to this string.
   * A sysctl_oid struct has the name string pointer.
   * On FreeBSD, struct sysctl_oid has:
   *   ... various fields ...
   *   char *oid_name;     (pointer to our string)
   *   int oid_number;
   *   ... */
  fprintf(fp, "\n  Scanning for pointers to string at 0x%lx...\n",
          (unsigned long)string_addr);

  intptr_t oid_addr = 0;

  for(size_t off = 0; off < 64UL * 1024 * 1024; off += chunk_sz) {
    int ret = kernel_copyout(kdata + off, buf, chunk_sz);
    if(ret) break;

    for(size_t i = 0; i + 8 <= chunk_sz; i += 8) {
      intptr_t ptr = *(intptr_t *)&buf[i];
      if(ptr == string_addr) {
        intptr_t found_at = kdata + off + i;
        fprintf(fp, "  Pointer to string found at 0x%lx (kdata+0x%lx)\n",
                (unsigned long)found_at, (unsigned long)(found_at - kdata));

        /* This is likely the oid_name field of sysctl_oid.
         * On FreeBSD, the struct layout varies by version but
         * the key fields around oid_name are:
         *   oid_handler (function pointer)
         *   oid_fmt
         *   oid_arg1 (void* - for integers, points to the variable)
         *   oid_arg2 (int - for integers, stores the value or size)
         *   oid_name
         *   oid_number
         *
         * Let's dump 256 bytes around this pointer to analyze the struct. */

        size_t dump_start = (i >= 128) ? i - 128 : 0;
        size_t dump_end = (i + 128 < chunk_sz) ? i + 128 : chunk_sz;
        fprintf(fp, "\n  Struct dump around name pointer:\n");
        for(size_t di = dump_start; di < dump_end; di += 8) {
          intptr_t val = *(intptr_t *)&buf[di];
          fprintf(fp, "    0x%lx: %016lx",
                  (unsigned long)(kdata + off + di),
                  (unsigned long)val);
          /* Annotate if this looks like a kernel pointer */
          if((val & 0xFFFFFF0000000000UL) == 0xFFFFFF0000000000UL)
            fprintf(fp, "  <- kernel ptr");
          if(val == string_addr)
            fprintf(fp, "  <- oid_name");
          fprintf(fp, "\n");
        }

        oid_addr = found_at;

        /* FreeBSD 11 sysctl_oid layout (0x60 bytes):
         *   +0x00: oid_children  (SLIST_HEAD, 8 bytes)
         *   +0x08: oid_parent    (ptr, 8 bytes)
         *   +0x10: oid_link      (SLIST_ENTRY, 8 bytes)
         *   +0x18: oid_number    (int, 4 bytes) + oid_kind (uint, 4 bytes)
         *   +0x20: oid_arg1      (void*, 8 bytes)
         *   +0x28: oid_arg2      (intmax_t, 8 bytes)
         *   +0x30: oid_name      (char*, 8 bytes) <-- found_at points here
         *   +0x38: oid_handler   (function ptr)
         *   +0x40: oid_fmt       (char*)
         *   +0x48: oid_refcnt(4) + oid_running(4)
         *   +0x50: oid_descr     (char*)
         *   +0x58: oid_label     (char*)
         *
         * Confirmed from dump: entries are 0x60 apart, oid_kind at
         * name-0x18 = 0x80000002 = CTLTYPE_INT|CTLFLAG_RD.
         *
         * For sysctl_handle_int: if oid_arg1 is NULL, the value
         * comes from oid_arg2 directly (not through a pointer). */

        intptr_t struct_base = found_at - 0x30;
        fprintf(fp, "\n  sysctl_oid base = 0x%lx\n",
                (unsigned long)struct_base);

        /* Read oid_arg1 and oid_arg2 */
        intptr_t oid_arg1 = 0;
        int64_t oid_arg2 = 0;
        uint32_t oid_kind = 0;
        kernel_copyout(struct_base + 0x18 + 4, &oid_kind, 4);
        kernel_copyout(struct_base + 0x20, &oid_arg1, 8);
        kernel_copyout(struct_base + 0x28, &oid_arg2, 8);

        fprintf(fp, "  oid_kind = 0x%08x\n", oid_kind);
        fprintf(fp, "  oid_arg1 = 0x%lx%s\n", (unsigned long)oid_arg1,
                oid_arg1 == 0 ? " (NULL - value in arg2)" : "");
        fprintf(fp, "  oid_arg2 = %ld (0x%lx)\n", (long)oid_arg2,
                (unsigned long)oid_arg2);

        if(oid_arg1 == 0) {
          /* Value is stored inline in oid_arg2. Write 1 there. */
          intptr_t arg2_addr = struct_base + 0x28;
          fprintf(fp, "\n  Patching oid_arg2 at 0x%lx: 0 -> 1\n",
                  (unsigned long)arg2_addr);
          int32_t one = 1;
          kernel_copyin(&one, arg2_addr, 4);

          int check = -1;
          size_t clen = sizeof(check);
          sysctlbyname("machdep.check_genuine_devkit_for_psm",
                        &check, &clen, NULL, 0);
          fprintf(fp, "  After patch: machdep.check_genuine_devkit_for_psm = %d\n",
                  check);

          if(check == 1) {
            fprintf(fp, "  *** SUCCESS! sysctl patched via oid_arg2 ***\n");
            goto patched;
          }

          /* If that didn't work, maybe the layout is different.
           * Try writing to the 8 bytes before name (name-8) directly */
          fprintf(fp, "  arg2 patch didn't change sysctl, trying name-8...\n");
          intptr_t alt_addr = found_at - 8;
          kernel_copyin(&one, alt_addr, 4);

          check = -1;
          clen = sizeof(check);
          sysctlbyname("machdep.check_genuine_devkit_for_psm",
                        &check, &clen, NULL, 0);
          fprintf(fp, "  After name-8 patch: value = %d\n", check);

          if(check == 1) {
            fprintf(fp, "  *** SUCCESS! sysctl patched at name-8 ***\n");
            goto patched;
          }

          /* Also try name-16 (oid_arg1 offset in some layouts) */
          fprintf(fp, "  Trying name-16...\n");
          alt_addr = found_at - 16;
          kernel_copyin(&one, alt_addr, 4);

          check = -1;
          clen = sizeof(check);
          sysctlbyname("machdep.check_genuine_devkit_for_psm",
                        &check, &clen, NULL, 0);
          fprintf(fp, "  After name-16 patch: value = %d\n", check);

          if(check == 1) {
            fprintf(fp, "  *** SUCCESS! sysctl patched at name-16 ***\n");
            goto patched;
          }

          /* Revert name-16 if it didn't work */
          int32_t zero = 0;
          kernel_copyin(&zero, found_at - 16, 4);
        } else {
          /* Value is behind a pointer in oid_arg1. Write 1 there. */
          fprintf(fp, "\n  Patching *oid_arg1 at 0x%lx: val -> 1\n",
                  (unsigned long)oid_arg1);
          int32_t one = 1;
          kernel_copyin(&one, oid_arg1, 4);

          int check = -1;
          size_t clen = sizeof(check);
          sysctlbyname("machdep.check_genuine_devkit_for_psm",
                        &check, &clen, NULL, 0);
          fprintf(fp, "  After patch: machdep.check_genuine_devkit_for_psm = %d\n",
                  check);

          if(check == 1) {
            fprintf(fp, "  *** SUCCESS! sysctl patched via *oid_arg1 ***\n");
            goto patched;
          }
        }

        /* Also try making the sysctl writable by changing oid_kind
         * from CTLFLAG_RD to CTLFLAG_RW, then writing via sysctlbyname */
        fprintf(fp, "\n  Trying to make sysctl writable...\n");
        uint32_t new_kind = (oid_kind & ~0xF0000000U) | 0xC0000000U;
        fprintf(fp, "  Changing oid_kind 0x%08x -> 0x%08x\n", oid_kind, new_kind);
        kernel_copyin(&new_kind, struct_base + 0x18 + 4, 4);

        int new_val = 1;
        int werr = sysctlbyname("machdep.check_genuine_devkit_for_psm",
                        NULL, NULL, &new_val, sizeof(new_val));
        fprintf(fp, "  sysctl write after kind change: err=%d errno=%d\n",
                werr, errno);

        int check2 = -1;
        size_t clen2 = sizeof(check2);
        sysctlbyname("machdep.check_genuine_devkit_for_psm",
                      &check2, &clen2, NULL, 0);
        fprintf(fp, "  After writable+write: value = %d\n", check2);

        if(check2 == 1) {
          fprintf(fp, "  *** SUCCESS! sysctl patched via writable mode ***\n");
          goto patched;
        }

        /* Restore kind */
        kernel_copyin(&oid_kind, struct_base + 0x18 + 4, 4);

        break;
      }
    }
    if(oid_addr) break;
  }

  if(!oid_addr) {
    fprintf(fp, "  No pointer to string found\n");
  }

  free(buf);
  return;

patched:
  free(buf);

  fprintf(fp, "\n=== SYSCTL PATCHED SUCCESSFULLY ===\n");
  fprintf(fp, "  machdep.check_genuine_devkit_for_psm = 1\n");

  /* Also ensure IsDevKit stubs are patched */
  fprintf(fp, "\n  Post-patch checks:\n");
  fprintf(fp, "    sceKernelIsDevKit()  = %d\n", sceKernelIsDevKit());
  fprintf(fp, "    sceKernelIsTestKit() = %d\n", sceKernelIsTestKit());
  fprintf(fp, "    sceKernelIsCEX()     = %d\n", sceKernelIsCEX());
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
