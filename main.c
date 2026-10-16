/* PS5 payload: decode and print every flag that is set.
 * Build with the ps5-payload-sdk. */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ps5/kernel.h>
#include <ps5/payload.h>

#define OUT_DIR  "/data/testpayload"
#define OUT_FILE OUT_DIR "/flags.txt"

/* ---- SCE syscalls ---- */
typedef struct notify_request {
  char unused[45];
  char message[3075];
} notify_request_t;
int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);

typedef struct app_info {
  uint32_t app_id;
  uint64_t unknown1;
  char     title_id[14];
  char     unknown2[0x3c];
} app_info_t;
int sceKernelGetAppInfo(pid_t pid, app_info_t *info);
int sceKernelGetSafemode(unsigned int *);
int sceKernelGetAslrStatus(unsigned int *);
int sceKernelGetGPI(unsigned int *);
int sceKernelGetGPO(unsigned int *);

static void
notify(const char* msg) {
  notify_request_t req;
  memset(&req, 0, sizeof(req));
  strncpy(req.message, msg, sizeof(req.message) - 1);
  sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

static void
print_bits(FILE* fp, const char* label, const uint8_t* data, size_t len) {
  fprintf(fp, "  raw: 0x");
  for(size_t i = 0; i < len; i++)
    fprintf(fp, "%02x", data[i]);
  fprintf(fp, "\n");

  int any = 0;
  for(size_t i = 0; i < len; i++) {
    for(int b = 7; b >= 0; b--) {
      if(data[i] & (1 << b)) {
        fprintf(fp, "  [%s bit %zu] = 1\n", label, i * 8 + (7 - b));
        any = 1;
      }
    }
  }
  if(!any)
    fprintf(fp, "  (no bits set)\n");
}

/* ---- known bit meanings ---- */

/* security_flags byte at SECURITY_FLAGS+0x00 */
static const char* secflag_names[8] = {
  /* bit 0 */ "DEBUG_SETTING_MODE (debug settings enabled)",
  /* bit 1 */ "SYSTEM_INIT_DONE",
  /* bit 2 */ "ALLOW_UNSIGNED_CODE",
  /* bit 3 */ "ALLOW_MAPPED_WRITE_EXEC",
  /* bit 4 */ "ALLOW_UNVERIFIED_DISC",
  /* bit 5 */ "INTERNAL_PROCESS_MODE",
  /* bit 6 */ "ALLOW_DEBUG_PROCESSES",
  /* bit 7 */ "DEVKIT_MODE",
};

/* target ID values */
static const char*
targetid_name(uint8_t id) {
  switch(id) {
  case 0x00: return "UNKNOWN";
  case 0x01: return "RETAIL (CEX)";
  case 0x02: return "DEVKIT (DEX/TOOL)";
  case 0x82: return "TESTKIT (TESTING)";
  case 0x81: return "ARCADE";
  case 0xFF: return "AEOLIA (EMU)";
  default:   return "(unknown target)";
  }
}

/* QA flags: 16 bytes (128 bits) */
static const char* qaflags_names[] = {
  /* byte 0 */
  /* 0.0 */ "INTERNAL_DEV",
  /* 0.1 */ "QA_ENABLED",
  /* 0.2 */ "ALLOW_DEBUG_MENU",
  /* 0.3 */ "ALLOW_PS_BUTTON_POWER_OFF",
  /* 0.4 */ "ALLOW_FACTORY_RESET",
  /* 0.5 */ "ALLOW_USB_MASS_STORAGE",
  /* 0.6 */ "ALLOW_HOST_FS",
  /* 0.7 */ "ALLOW_UPDATE_FROM_USB",
  /* byte 1 */
  /* 1.0 */ "ALLOW_EXTERNAL_HDD_WITHOUT_FORMAT",
  /* 1.1 */ "ALLOW_UNFORMATTED_EXTERNAL_HDD",
  /* 1.2 */ "ALLOW_UPDATE_RETAIL_TO_DEVKIT",
  /* 1.3 */ "FAKE_FINALIZE",
  /* 1.4 */ "ALLOW_INSTALLATION_FROM_HOST",
  /* 1.5 */ "UNKOWN_1_5",
  /* 1.6 */ "UNKOWN_1_6",
  /* 1.7 */ "UNKOWN_1_7",
  /* byte 2 */
  /* 2.0 */ "ENABLE_TESTKIT_FEATURES",
  /* 2.1 */ "ENABLE_NP_ENV_SWITCHING",
  /* 2.2 */ "ENABLE_STORE_MODE",
  /* 2.3 */ "ENABLE_KIOSK_MODE",
  /* 2.4 */ "ENABLE_PSN_ACCESS_TRACE_LOG",
  /* 2.5 */ "UNKOWN_2_5",
  /* 2.6 */ "UNKOWN_2_6",
  /* 2.7 */ "UNKOWN_2_7",
  /* byte 3 */
  /* 3.0 */ "ALLOW_SAVEDATA_REPAIR",
  /* 3.1 */ "ALLOW_DISC_BUDGETTYPE",
  /* 3.2 */ "ALLOW_SYSTEM_LEVEL_DEBUGGER",
  /* 3.3 */ "ALLOW_MBUS_MONITOR",
  /* 3.4 */ "UNKOWN_3_4",
  /* 3.5 */ "UNKOWN_3_5",
  /* 3.6 */ "UNKOWN_3_6",
  /* 3.7 */ "UNKOWN_3_7",
};

/* SCE caps: 16 bytes (128 bits) - known capability flags */
static const char* scecaps_names[] = {
  /* byte 0 */
  /* 0.0 */ "PRIV_MAXFILES",
  /* 0.1 */ "PRIV_PROC_SETLOGIN",
  /* 0.2 */ "PRIV_MDBG",
  /* 0.3 */ "PRIV_PROCESS_JIT",
  /* 0.4 */ "PRIV_RANDOM_MMAP",
  /* 0.5 */ "PRIV_PTRACE",
  /* 0.6 */ "PRIV_VFS_READ",
  /* 0.7 */ "PRIV_VFS_WRITE",
  /* byte 1 */
  /* 1.0 */ "PRIV_SYSCTL_WR",
  /* 1.1 */ "PRIV_DRIVER_DEBUG",
  /* 1.2 */ "PRIV_JAIL_MOUNT",
  /* 1.3 */ "PRIV_DEBUG_ATTACH",
  /* 1.4 */ "PRIV_DEBUG_UNPRIVILEGED",
  /* 1.5 */ "PRIV_COREDUMP",
  /* 1.6 */ "PRIV_SCE_SYS",
  /* 1.7 */ "PRIV_SYSTEM_DYNLIB",
  /* byte 2 */
  /* 2.0 */ "PRIV_MOUNT",
  /* 2.1 */ "PRIV_UNMOUNT",
  /* 2.2 */ "PRIV_NFS",
  /* 2.3 */ "PRIV_KLD_LOAD",
  /* 2.4 */ "PRIV_DIRECT_MEM",
  /* 2.5 */ "PRIV_GPU_MAP",
  /* 2.6 */ "PRIV_NET_RAW",
  /* 2.7 */ "PRIV_NET_IFCONFIG",
};

/* SCE attrs: 32 bytes (256 bits) - known attribute flags */
static const char* sceattrs_names[] = {
  /* byte 0 */
  /* 0.0 */ "ATTR_IS_SYSTEM_PROCESS",
  /* 0.1 */ "ATTR_IS_DAEMON",
  /* 0.2 */ "ATTR_IS_DEBUGGABLE",
  /* 0.3 */ "ATTR_IS_GAME",
  /* 0.4 */ "ATTR_HAS_DYNAMIC_PRIORITY",
  /* 0.5 */ "ATTR_IS_VIDEOPLAYER",
  /* 0.6 */ "ATTR_HAS_USE_VIDEO_SERVICE",
  /* 0.7 */ "ATTR_HAS_USE_AUDIO_SERVICE",
};

static void
print_named_bits(FILE* fp, const uint8_t* data, size_t datalen,
                 const char** names, size_t nnames) {
  fprintf(fp, "  raw: 0x");
  for(size_t i = 0; i < datalen; i++)
    fprintf(fp, "%02x", data[i]);
  fprintf(fp, "\n");

  int any = 0;
  for(size_t i = 0; i < datalen; i++) {
    for(int b = 7; b >= 0; b--) {
      if(data[i] & (1 << b)) {
        size_t bitidx = i * 8 + (7 - b);
        if(bitidx < nnames && names[bitidx])
          fprintf(fp, "  [bit %3zu] SET  %s\n", bitidx, names[bitidx]);
        else
          fprintf(fp, "  [bit %3zu] SET  (unknown)\n", bitidx);
        any = 1;
      }
    }
  }
  if(!any)
    fprintf(fp, "  (no bits set)\n");
}

int
main(void) {
  FILE* fp;
  pid_t pid = getpid();
  uint32_t fw = kernel_get_fw_version();

  mkdir(OUT_DIR, 0777);

  fp = fopen(OUT_FILE, "w");
  if(!fp) {
    perror(OUT_FILE);
    notify("testpayload: failed to open " OUT_FILE);
    return 1;
  }

  fprintf(fp, "=== PS5 FLAGS DUMP ===\n");
  fprintf(fp, "fw_version: 0x%08x (%d.%02d-%03d.%03d)\n\n",
          fw,
          (fw >> 24) & 0xff, (fw >> 16) & 0xff,
          (fw >> 8) & 0xff, fw & 0xff);

  /* ---- SECURITY_FLAGS ---- */
  {
    uint8_t sf = kernel_getchar(KERNEL_ADDRESS_SECURITY_FLAGS);
    fprintf(fp, "--- SECURITY_FLAGS (@ 0x%lx) ---\n", KERNEL_ADDRESS_SECURITY_FLAGS);
    fprintf(fp, "  raw: 0x%02x\n", sf);
    for(int b = 0; b < 8; b++) {
      fprintf(fp, "  [bit %d] %s  %s\n",
              b,
              (sf & (1 << b)) ? "SET  " : "CLEAR",
              secflag_names[b]);
    }
    fprintf(fp, "\n");
  }

  /* ---- Extended SECURITY_FLAGS region (bytes 0x01..0x08) ---- */
  {
    uint8_t region[9];
    memset(region, 0, sizeof(region));
    kernel_copyout(KERNEL_ADDRESS_SECURITY_FLAGS, region, sizeof(region));
    fprintf(fp, "--- SECURITY_FLAGS extended region (9 bytes) ---\n");
    fprintf(fp, "  ");
    for(int i = 0; i < 9; i++)
      fprintf(fp, "%02x ", region[i]);
    fprintf(fp, "\n");
    fprintf(fp, "  [+0x00] security_flags: 0x%02x\n", region[0]);
    fprintf(fp, "  [+0x01] unknown_01:     0x%02x\n", region[1]);
    fprintf(fp, "  [+0x02] unknown_02:     0x%02x\n", region[2]);
    fprintf(fp, "  [+0x03] unknown_03:     0x%02x\n", region[3]);
    fprintf(fp, "  [+0x04] unknown_04:     0x%02x\n", region[4]);
    fprintf(fp, "  [+0x05] unknown_05:     0x%02x\n", region[5]);
    fprintf(fp, "  [+0x06] unknown_06:     0x%02x\n", region[6]);
    fprintf(fp, "  [+0x07] unknown_07:     0x%02x\n", region[7]);
    fprintf(fp, "  [+0x08] unknown_08:     0x%02x\n", region[8]);
    fprintf(fp, "\n");
  }

  /* ---- TARGET ID ---- */
  {
    uint8_t tid = kernel_getchar(KERNEL_ADDRESS_TARGETID);
    fprintf(fp, "--- TARGET ID (@ 0x%lx = SECFLAGS+0x09) ---\n",
            KERNEL_ADDRESS_TARGETID);
    fprintf(fp, "  value: 0x%02x = %s\n\n", tid, targetid_name(tid));
  }

  /* ---- QA FLAGS ---- */
  {
    uint8_t qaflags[16] = {0};
    kernel_get_qaflags(qaflags);
    fprintf(fp, "--- QA_FLAGS (@ 0x%lx = SECFLAGS+0x24, 16 bytes) ---\n",
            KERNEL_ADDRESS_QA_FLAGS);
    print_named_bits(fp, qaflags, sizeof(qaflags),
                     qaflags_names,
                     sizeof(qaflags_names)/sizeof(qaflags_names[0]));
    fprintf(fp, "\n");
  }

  /* ---- UTOKEN FLAGS ---- */
  {
    /* read 4 bytes at utoken flags to get the full field */
    uint8_t utflags[4] = {0};
    kernel_copyout(KERNEL_ADDRESS_UTOKEN_FLAGS, utflags, sizeof(utflags));
    fprintf(fp, "--- UTOKEN_FLAGS (@ 0x%lx = SECFLAGS+0x8C, 4 bytes) ---\n",
            KERNEL_ADDRESS_UTOKEN_FLAGS);
    fprintf(fp, "  raw: 0x%02x%02x%02x%02x\n",
            utflags[0], utflags[1], utflags[2], utflags[3]);
    print_bits(fp, "utoken", utflags, sizeof(utflags));
    fprintf(fp, "\n");
  }

  /* ---- Full SECFLAGS region hex dump (0x00..0x9F) ---- */
  {
    uint8_t region[0xA0];
    memset(region, 0, sizeof(region));
    if(!kernel_copyout(KERNEL_ADDRESS_SECURITY_FLAGS, region, sizeof(region))) {
      fprintf(fp, "--- FULL SECFLAGS REGION (0xA0 bytes) ---\n");
      fprintf(fp, "  base: 0x%lx\n", KERNEL_ADDRESS_SECURITY_FLAGS);
      for(int i = 0; i < 0xA0; i += 16) {
        fprintf(fp, "  +%02x: ", i);
        for(int j = 0; j < 16 && (i+j) < 0xA0; j++)
          fprintf(fp, "%02x ", region[i+j]);
        fprintf(fp, " ");
        for(int j = 0; j < 16 && (i+j) < 0xA0; j++) {
          uint8_t c = region[i+j];
          fprintf(fp, "%c", (c >= 0x20 && c < 0x7f) ? c : '.');
        }
        fprintf(fp, "\n");
      }
      fprintf(fp, "\n");
    }
  }

  /* ---- SCE UCRED: authid, caps, attrs for our process ---- */
  {
    uint8_t caps[16] = {0};
    uint8_t attrs[32] = {0};
    uint64_t authid = kernel_get_ucred_authid(pid);

    fprintf(fp, "--- SCE AUTHID (pid %d) ---\n", pid);
    fprintf(fp, "  value: 0x%016lx\n", authid);
    /* decode authid fields */
    fprintf(fp, "  program_type:  0x%02lx\n", (authid >> 56) & 0xff);
    fprintf(fp, "  program_attr:  0x%04lx\n", (authid >> 40) & 0xffff);
    fprintf(fp, "  program_id:    0x%010lx\n", authid & 0xffffffffffUL);
    fprintf(fp, "\n");

    fprintf(fp, "--- SCE CAPS (pid %d, 16 bytes) ---\n", pid);
    kernel_get_ucred_caps(pid, caps);
    print_named_bits(fp, caps, sizeof(caps),
                     scecaps_names,
                     sizeof(scecaps_names)/sizeof(scecaps_names[0]));
    fprintf(fp, "\n");

    fprintf(fp, "--- SCE ATTRS (pid %d, 32 bytes) ---\n", pid);
    kernel_get_ucred_attrs(pid, attrs);
    print_named_bits(fp, attrs, sizeof(attrs),
                     sceattrs_names,
                     sizeof(sceattrs_names)/sizeof(sceattrs_names[0]));
    fprintf(fp, "\n");
  }

  /* ---- UCRED privilege flags ---- */
  {
    fprintf(fp, "--- UCRED IDS (pid %d) ---\n", pid);
    fprintf(fp, "  uid:     %d\n", kernel_get_ucred_uid(pid));
    fprintf(fp, "  ruid:    %d\n", kernel_get_ucred_ruid(pid));
    fprintf(fp, "  svuid:   %d\n", kernel_get_ucred_svuid(pid));
    fprintf(fp, "  rgid:    %d\n", kernel_get_ucred_rgid(pid));
    fprintf(fp, "  svgid:   %d\n", kernel_get_ucred_svgid(pid));
    fprintf(fp, "  prison:  0x%lx (0 = unjailed)\n", kernel_get_ucred_prison(pid));
    fprintf(fp, "\n");
  }

  /* ---- APP INFO flags ---- */
  {
    app_info_t app = {0};
    if(!sceKernelGetAppInfo(pid, &app)) {
      fprintf(fp, "--- APP INFO (pid %d) ---\n", pid);
      fprintf(fp, "  app_id:    %u\n", app.app_id);
      fprintf(fp, "  title_id:  %s\n", app.title_id);
      fprintf(fp, "\n");
    }
  }

  /* ---- MISC FLAGS ---- */
  {
    unsigned int val = 0;
    fprintf(fp, "--- MISC FLAGS ---\n");

    if(!sceKernelGetSafemode(&val))
      fprintf(fp, "  safemode:     %u (%s)\n", val, val ? "ON" : "OFF");

    if(!sceKernelGetAslrStatus(&val))
      fprintf(fp, "  aslr:         %u (%s)\n", val, val ? "ENABLED" : "DISABLED");

    if(!sceKernelGetGPI(&val))
      fprintf(fp, "  GPI:          0x%08x\n", val);

    if(!sceKernelGetGPO(&val))
      fprintf(fp, "  GPO:          0x%08x\n", val);

    fprintf(fp, "\n");
  }

  /* ---- Also dump flags for pid 0 (kernel) and pid 1 (init) ---- */
  {
    static const pid_t pids[] = {0, 1};
    static const char* pnames[] = {"kernel (pid 0)", "init (pid 1)"};
    for(int p = 0; p < 2; p++) {
      pid_t tpid = pids[p];
      uint8_t caps[16] = {0};
      uint8_t attrs[32] = {0};

      intptr_t proc = kernel_get_proc(tpid);
      if(!proc) continue;

      fprintf(fp, "--- %s ---\n", pnames[p]);
      fprintf(fp, "  authid: 0x%016lx\n", kernel_get_ucred_authid(tpid));

      kernel_get_ucred_caps(tpid, caps);
      fprintf(fp, "  caps:   0x");
      for(int i = 0; i < 16; i++) fprintf(fp, "%02x", caps[i]);
      fprintf(fp, "\n");

      kernel_get_ucred_attrs(tpid, attrs);
      fprintf(fp, "  attrs:  0x");
      for(int i = 0; i < 32; i++) fprintf(fp, "%02x", attrs[i]);
      fprintf(fp, "\n");

      fprintf(fp, "  uid:    %d\n", kernel_get_ucred_uid(tpid));
      fprintf(fp, "  prison: 0x%lx\n", kernel_get_ucred_prison(tpid));
      fprintf(fp, "\n");
    }
  }

  fclose(fp);

  /* also print to stdout so it comes back over nc */
  {
    FILE* rd = fopen(OUT_FILE, "r");
    if(rd) {
      char line[512];
      while(fgets(line, sizeof(line), rd))
        printf("%s", line);
      fclose(rd);
    }
  }

  notify("testpayload: flags dumped to " OUT_FILE);
  return 0;
}
