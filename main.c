/* PS5 payload: comprehensive flag decoder + kernel struct dumps.
 * Build with the ps5-payload-sdk. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <ps5/kernel.h>
#include <ps5/payload.h>

#define OUT_DIR  "/data/testpayload"

/* ---- CRT-internal symbols ---- */
extern const unsigned long KERNEL_ADDRESS_DMAP_BASE;
extern const unsigned long KERNEL_ADDRESS_IOMMU_SOFTC;
extern const unsigned long KERNEL_OFFSET_VMSPACE_P_ROOT;
extern const unsigned long KERNEL_OFFSET_UCRED_CR_SVGID;
extern const unsigned long KERNEL_OFFSET_UCRED_CR_PRISON;

/* IOMMU DMA write functions — bypass CPU page protections (FW >= 7.00) */
int kernel_iommu_copyin(const void *uaddr, unsigned long kaddr, unsigned long len);
int kernel_iommu_setchar(unsigned long kaddr, unsigned char val);

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
int  sceKernelGetAppInfo(pid_t pid, app_info_t *info);
int  sceKernelGetHwModelName(char *);
long sceKernelGetCpuFrequency(void);
int  sceKernelGetCpuTemperature(int *);
int  sceKernelGetSocSensorTemperature(int, int *);
int  sceKernelGetSocPowerConsumption(int *);
int  sceKernelGetProsperoSystemSwVersion(unsigned int *);
int  sceKernelGetOpenPsId(char[16]);
int  sceKernelGetProductCode(unsigned int *);
int  sceKernelGetProductStr(char *);
int  sceKernelGetMainSocId(char[8]);
int  sceKernelGetSubsysId(unsigned int *);
int  sceKernelGetDirectMemorySize(size_t *);
int  sceKernelGetPhysPageSize(void);
int  sceKernelGetCurrentCpu(void);
int  sceKernelGetProcessName(pid_t, char *);
int  sceKernelGetProcessType(pid_t, unsigned int *);
int  sceKernelGetSafemode(unsigned int *);
int  sceKernelGetAslrStatus(unsigned int *);
int  sceKernelGetBasicProductShape(unsigned int *);
long sceKernelGetTscFrequency(void);
int  sceKernelGetGPI(unsigned int *);
int  sceKernelIsDevKit(void);
int  sceKernelIsTestKit(void);
int  sceKernelIsGenuineDevKit(void);
int  sceKernelIsGenuineTestKit(void);
int  sceKernelIsCEX(void);

/* notification API for deep links */
int sceNotificationSend(int userId, int isLogged, const char* payload);

/* registry manager */
int sceRegMgrGetInt(unsigned int regId, int *value);
int sceRegMgrSetInt(unsigned int regId, int value);
int sceRegMgrGetStr(unsigned int regId, char *buf, size_t size);
int sceRegMgrSetStr(unsigned int regId, const char *buf, size_t size);

/* DEVENV registry key IDs (from ps5-payload-dev/regdump regmgr.h) */
#define REGKEY_DEVENV_HOST_devkitname        2013331712U
#define REGKEY_DEVENV_TOOL_host_overlay      2013438976U
#define REGKEY_DEVENV_TOOL_shell_debug       2013440256U
#define REGKEY_DEVENV_TOOL_compositor_dbg    2013441280U
#define REGKEY_DEVENV_TOOL_qaflag_masq       2013442560U
#define REGKEY_DEVENV_TOOL_trc_notify        2013422592U
#define REGKEY_DEVENV_TOOL_trc_notify_number 2013422848U
#define REGKEY_DEVENV_TOOL_SHELLUI_debug_menu   2013448449U
#define REGKEY_DEVENV_TOOL_SHELLUI_disp_titleid 2013448470U
#define REGKEY_DEVENV_TOOL_SHELLUI_content_info 2013448648U
#define REGKEY_SYSTEM_SPECIFIC_show_mode     42336768U
#define REGKEY_SYSTEM_language               33685504U

int  sceKernelGetGPO(unsigned int *);
int  sceKernelGetSystemSwVersion(char *);
int  sceKernelGetUpdVersion(char *);
int  sceKernelGetBuildNumber(unsigned int *);
int  sceKernelGetCpumode(unsigned int *);

/* ---- helpers ---- */
static void
notify(const char* msg) {
  notify_request_t req;
  memset(&req, 0, sizeof(req));
  strncpy(req.message, msg, sizeof(req.message) - 1);
  sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

static void
hexdump(FILE* fp, const uint8_t* data, size_t len, intptr_t base) {
  for(size_t i = 0; i < len; i += 16) {
    if(base)
      fprintf(fp, "  %016lx: ", base + i);
    else
      fprintf(fp, "  +%04zx: ", i);
    for(size_t j = 0; j < 16 && (i+j) < len; j++)
      fprintf(fp, "%02x ", data[i+j]);
    for(size_t j = (len - i < 16 ? len - i : 16); j < 16; j++)
      fprintf(fp, "   ");
    fprintf(fp, " ");
    for(size_t j = 0; j < 16 && (i+j) < len; j++) {
      uint8_t c = data[i+j];
      fprintf(fp, "%c", (c >= 0x20 && c < 0x7f) ? c : '.');
    }
    fprintf(fp, "\n");
  }
}

/* Bit decoder: LSB-first within each byte (matching PS5 convention) */
static void
decode_bits_lsb(FILE* fp, const uint8_t* data, size_t datalen,
                const char** names, size_t nnames) {
  fprintf(fp, "  raw: 0x");
  for(size_t i = 0; i < datalen; i++)
    fprintf(fp, "%02x", data[i]);
  fprintf(fp, "\n");

  int any = 0;
  for(size_t i = 0; i < datalen; i++) {
    for(int b = 0; b < 8; b++) {
      if(data[i] & (1 << b)) {
        size_t bitidx = i * 8 + b;
        if(bitidx < nnames && names[bitidx])
          fprintf(fp, "  [bit %3zu] SET  %s\n", bitidx, names[bitidx]);
        else
          fprintf(fp, "  [bit %3zu] SET\n", bitidx);
        any = 1;
      }
    }
  }
  if(!any)
    fprintf(fp, "  (no bits set)\n");
}

/* ---- Known flag bit names ---- */

/* SECURITY_FLAGS byte */
static const char* secflag_names[] = {
  /* 0 */ "DEBUG_SETTING_MODE",
  /* 1 */ "SYSTEM_INIT_DONE",
  /* 2 */ "ALLOW_UNSIGNED_CODE",
  /* 3 */ "ALLOW_MAPPED_WRITE_EXEC",
  /* 4 */ "ALLOW_UNVERIFIED_DISC",
  /* 5 */ "INTERNAL_PROCESS_MODE",
  /* 6 */ "ALLOW_DEBUG_PROCESSES",
  /* 7 */ "DEVKIT_MODE",
};

/* TARGET ID */
static const char*
targetid_name(uint8_t id) {
  switch(id) {
  case 0x01: return "RETAIL (CEX)";
  case 0x02: return "DEVKIT (DEX/TOOL)";
  case 0x81: return "ARCADE";
  case 0x82: return "TESTKIT (TESTING)";
  case 0xFF: return "AEOLIA (EMU)";
  default:   return "(unknown)";
  }
}

/* QA_FLAGS: 16 bytes, LSB-first per byte */
static const char* qa_names[] = {
  /* byte 0 */
  /* 0  */ "INTERNAL_DEV",
  /* 1  */ "QA_ENABLED",
  /* 2  */ "ALLOW_DEBUG_MENU",
  /* 3  */ "ALLOW_PS_BUTTON_POWER_OFF",
  /* 4  */ "ALLOW_FACTORY_RESET",
  /* 5  */ "ALLOW_USB_MASS_STORAGE",
  /* 6  */ "ALLOW_HOST_FS",
  /* 7  */ "ALLOW_UPDATE_FROM_USB",
  /* byte 1 */
  /* 8  */ "ALLOW_EXTERNAL_HDD_NO_FORMAT",
  /* 9  */ "ALLOW_UNFORMATTED_EXT_HDD",
  /* 10 */ "ALLOW_UPDATE_RETAIL_TO_DEVKIT",
  /* 11 */ "FAKE_FINALIZE",
  /* 12 */ "ALLOW_INSTALLATION_FROM_HOST",
  /* 13 */ "UNKNOWN_1_5",
  /* 14 */ "UNKNOWN_1_6",
  /* 15 */ "UNKNOWN_1_7",
  /* byte 2 */
  /* 16 */ "ENABLE_TESTKIT_FEATURES",
  /* 17 */ "ENABLE_NP_ENV_SWITCHING",
  /* 18 */ "ENABLE_STORE_MODE",
  /* 19 */ "ENABLE_KIOSK_MODE",
  /* 20 */ "ENABLE_PSN_ACCESS_TRACE_LOG",
  /* 21 */ "UNKNOWN_2_5",
  /* 22 */ "UNKNOWN_2_6",
  /* 23 */ "UNKNOWN_2_7",
  /* byte 3 */
  /* 24 */ "ALLOW_SAVEDATA_REPAIR",
  /* 25 */ "ALLOW_DISC_BUDGETTYPE",
  /* 26 */ "ALLOW_SYSTEM_LEVEL_DEBUGGER",
  /* 27 */ "ALLOW_MBUS_MONITOR",
  /* 28 */ "UNKNOWN_3_4",
  /* 29 */ "UNKNOWN_3_5",
  /* 30 */ "UNKNOWN_3_6",
  /* 31 */ "UNKNOWN_3_7",
  /* byte 4 */
  /* 32 */ "USE_SOFTWAGNER_FOR_ACMGR",
  /* 33 */ "USE_SOFTWAGNER_FOR_RCMGR",
  /* 34 */ "WEAKEN_PORT_RESTRICTION",
  /* 35 */ "ENABLE_FAKE_SHAREFC",
  /* 36 */ "UNKNOWN_4_4",
  /* 37 */ "UNKNOWN_4_5",
  /* 38 */ "UNKNOWN_4_6",
  /* 39 */ "UNKNOWN_4_7",
};

/* SCE CAPS: 16 bytes, LSB-first per byte
 * Based on FreeBSD priv.h mapping + SCE extensions */
static const char* scecaps_names[] = {
  /* byte 0 */
  /* 0  */ "PRIV_KERN_SCHED",
  /* 1  */ "PRIV_KERN_SETTIME",
  /* 2  */ "PRIV_KERN_NFSD",
  /* 3  */ "PRIV_KERN_NFSCLIENT",
  /* 4  */ "PRIV_KERN_AUDIT",
  /* 5  */ "PRIV_KERN_RTSIGNAL",
  /* 6  */ "PRIV_KERN_SWAPSPACE",
  /* 7  */ "PRIV_KERN_RESOURCE",
  /* byte 1 */
  /* 8  */ "PRIV_KERN_CHROOT",
  /* 9  */ "PRIV_KERN_PRISON",
  /* 10 */ "PRIV_KERN_MLOCK",
  /* 11 */ "PRIV_KERN_MAXPROC",
  /* 12 */ "PRIV_KERN_MAXFILES",
  /* 13 */ "PRIV_KERN_LOGINCTX",
  /* 14 */ "PRIV_KERN_MDBG",
  /* 15 */ "PRIV_KERN_JIT",
  /* byte 2 */
  /* 16 */ "PRIV_KERN_RANDOM_MMAP",
  /* 17 */ "PRIV_PROC_TRACE",
  /* 18 */ "PRIV_PROC_SETLOGIN",
  /* 19 */ "PRIV_PROC_SETRLIMIT",
  /* 20 */ "PRIV_PROC_SETPRIORITY",
  /* 21 */ "PRIV_PROC_LIMIT",
  /* 22 */ "PRIV_PROC_SETCPU",
  /* 23 */ "PRIV_PROC_COREDUMP",
  /* byte 3 */
  /* 24 */ "PRIV_CRED_SETUID",
  /* 25 */ "PRIV_CRED_SETGID",
  /* 26 */ "PRIV_CRED_SETSGROUPS",
  /* 27 */ "PRIV_IPC_ADMIN",
  /* 28 */ "PRIV_IPC_SHM",
  /* 29 */ "PRIV_IPC_MSG",
  /* 30 */ "PRIV_IPC_SEM",
  /* 31 */ "PRIV_IPC_POSIX",
  /* byte 4 */
  /* 32 */ "PRIV_NET_BRIDGE",
  /* 33 */ "PRIV_NET_LAGG",
  /* 34 */ "PRIV_NET_ROUTE",
  /* 35 */ "PRIV_NET_TAP",
  /* 36 */ "PRIV_NET_SETIFMTU",
  /* 37 */ "PRIV_NET_SETIFFLAGS",
  /* 38 */ "PRIV_NET_SETIFCAP",
  /* 39 */ "PRIV_NET_SETIFNAME",
  /* byte 5 */
  /* 40 */ "PRIV_NET_SETIFMETRIC",
  /* 41 */ "PRIV_NET_SETIFPHYS",
  /* 42 */ "PRIV_NET_SETIFMAC",
  /* 43 */ "PRIV_NET_ADDMULTI",
  /* 44 */ "PRIV_NET_DELMULTI",
  /* 45 */ "PRIV_NET_HWIOCTL",
  /* 46 */ "PRIV_NET_SETLLADDR",
  /* 47 */ "PRIV_NET_ADDIFGROUP",
  /* byte 6 */
  /* 48 */ "PRIV_NET_DELIFGROUP",
  /* 49 */ "PRIV_NET_IFCREATE",
  /* 50 */ "PRIV_NET_IFDESTROY",
  /* 51 */ "PRIV_NET_ADDIFADDR",
  /* 52 */ "PRIV_NET_DELIFADDR",
  /* 53 */ "PRIV_NET_RAWSOCK",
  /* 54 */ "PRIV_NET_SETIFVNET",
  /* 55 */ "PRIV_NET_SETIFSNDBUF",
  /* byte 7 */
  /* 56 */ "PRIV_NET_SETIFRCVBUF",
  /* 57 */ "PRIV_NET_BINDANY",
  /* 58 */ "PRIV_NET_GRE",
  /* 59 */ "PRIV_NET_BPF",
  /* 60 */ "PRIV_NET_RAW_PROTOCOL",
  /* 61 */ "PRIV_NET_NECP",
  /* 62 */ "PRIV_NET_IPSEC",
  /* 63 */ "PRIV_NET_VLAN",
  /* byte 8 */
  /* 64 */ "PRIV_VFS_READ",
  /* 65 */ "PRIV_VFS_WRITE",
  /* 66 */ "PRIV_VFS_ADMIN",
  /* 67 */ "PRIV_VFS_EXEC",
  /* 68 */ "PRIV_VFS_LOOKUP",
  /* 69 */ "PRIV_VFS_BLOCKRESERVE",
  /* 70 */ "PRIV_VFS_CHFLAGS_DEV",
  /* 71 */ "PRIV_VFS_CHOWN",
  /* byte 9 */
  /* 72 */ "PRIV_VFS_CHROOT",
  /* 73 */ "PRIV_VFS_RETAINSUGID",
  /* 74 */ "PRIV_VFS_FCHROOT",
  /* 75 */ "PRIV_VFS_LINK",
  /* 76 */ "PRIV_VFS_SETGID",
  /* 77 */ "PRIV_VFS_STICKYDIR",
  /* 78 */ "PRIV_VFS_SYSFLAGS",
  /* 79 */ "PRIV_VFS_UNMOUNT",
  /* byte 10 */
  /* 80 */ "PRIV_VFS_STAT",
  /* 81 */ "PRIV_VFS_MOUNT",
  /* 82 */ "PRIV_VFS_MOUNT_OWNER",
  /* 83 */ "PRIV_VFS_MOUNT_EXPORTED",
  /* 84 */ "PRIV_VFS_MOUNT_PERM",
  /* 85 */ "PRIV_VFS_MOUNT_SUIDDIR",
  /* 86 */ "PRIV_VFS_MOUNT_NONUSER",
  /* 87 */ "PRIV_VFS_SETATTR",
  /* byte 11 */
  /* 88 */ "PRIV_VFS_NFSD",
  /* 89 */ "PRIV_VFS_GENERATION",
  /* 90 */ "PRIV_VFS_EXTATTR_SYSTEM",
  /* 91 */ "PRIV_VFS_MKNOD_BAD",
  /* 92 */ "PRIV_VFS_MKNOD_DEV",
  /* 93 */ "PRIV_VFS_MKNOD_WHT",
  /* 94 */ "PRIV_VFS_FHOPEN",
  /* 95 */ "PRIV_VFS_FHSTAT",
  /* byte 12 */
  /* 96 */ "PRIV_VFS_FHSTATFS",
  /* 97 */ "PRIV_SCE_SYS_DYNLIB",
  /* 98 */ "PRIV_SCE_SYS_DRIVER",
  /* 99 */ "PRIV_SCE_SYS_PROC",
  /* 100*/ "PRIV_SCE_SYS_SYSCTL",
  /* 101*/ "PRIV_SCE_SYS_JAIL",
  /* 102*/ "PRIV_SCE_SYS_DEVFS",
  /* 103*/ "PRIV_SCE_SYS_ACCT",
  /* byte 13..15 */
};

/* SCE ATTRS: 32 bytes, LSB-first per byte */
static const char* sceattrs_names[] = {
  /* byte 0 */
  /* 0  */ "IS_SYSTEM_PROCESS",
  /* 1  */ "IS_DAEMON",
  /* 2  */ "IS_DEBUGGABLE",
  /* 3  */ "IS_GAME",
  /* 4  */ "HAS_DYNAMIC_PRIORITY",
  /* 5  */ "IS_VIDEOPLAYER",
  /* 6  */ "USE_VIDEO_SERVICE",
  /* 7  */ "USE_AUDIO_SERVICE",
  /* byte 1 */
  /* 8  */ "IS_APPLICATION",
  /* 9  */ "IS_MINI_APP",
  /* 10 */ "IS_BIG_APP",
  /* 11 */ "ALLOW_DEVKIT_DEBUGGING",
  /* 12 */ "ALLOW_TESTKIT_DEBUGGING",
  /* 13 */ "ALLOW_REMOTE_DEBUGGING",
  /* 14 */ "IS_SUSPENDABLE",
  /* 15 */ "IS_KILLABLE",
  /* byte 2 */
  /* 16 */ "USE_GPU",
  /* 17 */ "USE_GPU_COMPUTE",
  /* 18 */ "USE_GPU_DEBUG",
  /* 19 */ "ALLOW_COREDUMP",
  /* 20 */ "IS_DECID_PROCESS",
  /* 21 */ "ALLOW_DIRECT_MEMORY",
  /* 22 */ "ALLOW_FLEXIBLE_MEMORY",
  /* 23 */ "USE_NETWORK",
};

/* authid program types */
static const char*
authid_progtype(uint8_t pt) {
  switch(pt) {
  case 0x00: return "NONE";
  case 0x01: return "FAKE_SELF";
  case 0x04: return "NPDRM_EXEC";
  case 0x05: return "NPDRM_DYNLIB";
  case 0x08: return "SYSTEM_EXEC";
  case 0x09: return "SYSTEM_DYNLIB";
  case 0x0C: return "HOST_KERNEL";
  case 0x0E: return "SECURE_MODULE";
  case 0x0F: return "SECURE_KERNEL";
  case 0x48: return "PROSPERO_OS (SCE signed)";
  case 0x49: return "PROSPERO_USER";
  default:   return "(unknown)";
  }
}

/* ========== FLAGS.TXT ========== */
static void
write_flags(void) {
  FILE* fp;
  char path[256];
  pid_t pid = getpid();

  snprintf(path, sizeof(path), "%s/flags.txt", OUT_DIR);
  fp = fopen(path, "w");
  if(!fp) { perror(path); return; }

  uint32_t fw = kernel_get_fw_version();
  fprintf(fp, "=== PS5 FLAGS DUMP ===\n");
  fprintf(fp, "fw_version: 0x%08x (%d.%02d-%03d.%03d)\n\n",
          fw, (fw>>24)&0xff, (fw>>16)&0xff, (fw>>8)&0xff, fw&0xff);

  /* SECURITY_FLAGS byte */
  {
    uint8_t sf = kernel_getchar(KERNEL_ADDRESS_SECURITY_FLAGS);
    fprintf(fp, "--- SECURITY_FLAGS (@ 0x%lx) ---\n", KERNEL_ADDRESS_SECURITY_FLAGS);
    decode_bits_lsb(fp, &sf, 1, secflag_names, 8);
    fprintf(fp, "\n");
  }

  /* TARGET ID */
  {
    uint8_t tid = kernel_getchar(KERNEL_ADDRESS_TARGETID);
    fprintf(fp, "--- TARGET ID (@ 0x%lx) ---\n", KERNEL_ADDRESS_TARGETID);
    fprintf(fp, "  value: 0x%02x = %s\n\n", tid, targetid_name(tid));
  }

  /* QA FLAGS */
  {
    uint8_t qa[16] = {0};
    kernel_get_qaflags(qa);
    fprintf(fp, "--- QA_FLAGS (@ 0x%lx, 16 bytes) ---\n", KERNEL_ADDRESS_QA_FLAGS);
    decode_bits_lsb(fp, qa, sizeof(qa), qa_names, sizeof(qa_names)/sizeof(qa_names[0]));
    fprintf(fp, "\n");
  }

  /* UTOKEN FLAGS - read 16 bytes to get the full field */
  {
    uint8_t ut[16] = {0};
    kernel_copyout(KERNEL_ADDRESS_UTOKEN_FLAGS, ut, sizeof(ut));
    fprintf(fp, "--- UTOKEN_FLAGS (@ 0x%lx, 16 bytes) ---\n", KERNEL_ADDRESS_UTOKEN_FLAGS);
    decode_bits_lsb(fp, ut, sizeof(ut), NULL, 0);
    fprintf(fp, "\n");
  }

  /* SCE AUTHID */
  {
    uint64_t authid = kernel_get_ucred_authid(pid);
    uint8_t pt = (authid >> 56) & 0xff;
    fprintf(fp, "--- SCE AUTHID (pid %d) ---\n", pid);
    fprintf(fp, "  value:        0x%016lx\n", authid);
    fprintf(fp, "  program_type: 0x%02x = %s\n", pt, authid_progtype(pt));
    fprintf(fp, "  program_attr: 0x%04lx\n", (authid >> 40) & 0xffff);
    fprintf(fp, "  program_id:   0x%010lx\n", authid & 0xffffffffffUL);
    fprintf(fp, "\n");
  }

  /* SCE CAPS */
  {
    uint8_t caps[16] = {0};
    kernel_get_ucred_caps(pid, caps);
    fprintf(fp, "--- SCE CAPS (pid %d, 16 bytes = 128 bits) ---\n", pid);
    decode_bits_lsb(fp, caps, sizeof(caps), scecaps_names,
                    sizeof(scecaps_names)/sizeof(scecaps_names[0]));
    fprintf(fp, "\n");
  }

  /* SCE ATTRS */
  {
    uint8_t attrs[32] = {0};
    kernel_get_ucred_attrs(pid, attrs);
    fprintf(fp, "--- SCE ATTRS (pid %d, 32 bytes = 256 bits) ---\n", pid);
    decode_bits_lsb(fp, attrs, sizeof(attrs), sceattrs_names,
                    sizeof(sceattrs_names)/sizeof(sceattrs_names[0]));
    fprintf(fp, "\n");
  }

  /* UCRED IDs */
  {
    fprintf(fp, "--- UCRED (pid %d) ---\n", pid);
    fprintf(fp, "  uid:    %d\n", kernel_get_ucred_uid(pid));
    fprintf(fp, "  ruid:   %d\n", kernel_get_ucred_ruid(pid));
    fprintf(fp, "  svuid:  %d\n", kernel_get_ucred_svuid(pid));
    fprintf(fp, "  rgid:   %d\n", kernel_get_ucred_rgid(pid));
    fprintf(fp, "  svgid:  %d\n", kernel_get_ucred_svgid(pid));
    intptr_t prison = kernel_get_ucred_prison(pid);
    fprintf(fp, "  prison: 0x%lx%s\n", prison,
            (prison == KERNEL_ADDRESS_PRISON0) ? " (PRISON0 = unjailed)" : "");
    fprintf(fp, "\n");
  }

  /* APP INFO */
  {
    app_info_t app = {0};
    if(!sceKernelGetAppInfo(pid, &app)) {
      fprintf(fp, "--- APP INFO (pid %d) ---\n", pid);
      fprintf(fp, "  app_id:   %u\n", app.app_id);
      fprintf(fp, "  title_id: %s\n", app.title_id);
      fprintf(fp, "\n");
    }
  }

  /* MISC FLAGS */
  {
    unsigned int val = 0;
    fprintf(fp, "--- MISC FLAGS ---\n");
    if(!sceKernelGetSafemode(&val))
      fprintf(fp, "  safemode:  %u (%s)\n", val, val ? "ON" : "OFF");
    if(!sceKernelGetAslrStatus(&val))
      fprintf(fp, "  aslr:      %u (%s)\n", val, val ? "ENABLED" : "DISABLED");
    if(!sceKernelGetGPI(&val))
      fprintf(fp, "  GPI:       0x%08x\n", val);
    if(!sceKernelGetGPO(&val))
      fprintf(fp, "  GPO:       0x%08x\n", val);
    if(!sceKernelGetCpumode(&val))
      fprintf(fp, "  cpumode:   0x%x\n", val);
    if(!sceKernelGetBuildNumber(&val))
      fprintf(fp, "  build_num: %u\n", val);
    fprintf(fp, "\n");
  }

  /* Full secflags region hex dump */
  {
    uint8_t region[0xA0];
    memset(region, 0, sizeof(region));
    if(!kernel_copyout(KERNEL_ADDRESS_SECURITY_FLAGS, region, sizeof(region))) {
      fprintf(fp, "--- SECFLAGS REGION (0xA0 bytes @ 0x%lx) ---\n",
              KERNEL_ADDRESS_SECURITY_FLAGS);
      fprintf(fp, "  +00 security_flags | +09 targetid | +0B subsys\n");
      fprintf(fp, "  +14 openpsid(16B)  | +24 qa_flags(16B)\n");
      fprintf(fp, "  +8C utoken_flags\n\n");
      hexdump(fp, region, sizeof(region), 0);
      fprintf(fp, "\n");
    }
  }

  /* Flags for kernel (pid 0), init (pid 1), and SceShellCore */
  {
    fprintf(fp, "--- COMPARISON: other processes ---\n\n");
    /* find SceShellCore pid */
    int mib[4] = {1, 14, 8, 0};
    size_t buf_size = 0;
    uint8_t *buf = NULL;
    pid_t shellcore_pid = -1;

    if(!sysctl(mib, 4, 0, &buf_size, 0, 0)) {
      buf = malloc(buf_size);
      if(buf && !sysctl(mib, 4, buf, &buf_size, 0, 0)) {
        for(uint8_t *ptr = buf; ptr < (buf + buf_size);) {
          int ki_structsize = *(int*)ptr;
          pid_t ki_pid = *(pid_t*)&ptr[72];
          char *ki_tdname = (char*)&ptr[447];
          if(ki_structsize <= 0) break;
          if(!strcmp(ki_tdname, "SceShellCore"))
            shellcore_pid = ki_pid;
          ptr += ki_structsize;
        }
      }
      free(buf);
    }

    pid_t compare_pids[4] = {0, 1, shellcore_pid, pid};
    const char* compare_names[4] = {"kernel", "init (mini-syscore)", "SceShellCore", "payload (self)"};

    for(int p = 0; p < 4; p++) {
      pid_t tpid = compare_pids[p];
      if(tpid < 0) continue;
      intptr_t proc = kernel_get_proc(tpid);
      if(!proc && tpid != 0) continue;

      uint8_t caps[16] = {0};
      uint8_t attrs[32] = {0};
      kernel_get_ucred_caps(tpid, caps);
      kernel_get_ucred_attrs(tpid, attrs);

      fprintf(fp, "  [%s (pid %d)]\n", compare_names[p], tpid);
      fprintf(fp, "    authid: 0x%016lx (%s)\n",
              kernel_get_ucred_authid(tpid),
              authid_progtype((kernel_get_ucred_authid(tpid) >> 56) & 0xff));
      fprintf(fp, "    caps:   0x");
      for(int i = 0; i < 16; i++) fprintf(fp, "%02x", caps[i]);
      fprintf(fp, "\n    attrs:  0x");
      for(int i = 0; i < 32; i++) fprintf(fp, "%02x", attrs[i]);
      fprintf(fp, "\n    uid:    %d  prison: 0x%lx\n\n",
              kernel_get_ucred_uid(tpid), kernel_get_ucred_prison(tpid));
    }
  }

  fclose(fp);
  printf("wrote %s\n", path);
}

/* ========== RAW STRUCT DUMPS ========== */
static void
write_struct_dumps(void) {
  FILE* fp;
  char path[256];
  pid_t pid = getpid();

  snprintf(path, sizeof(path), "%s/structs.txt", OUT_DIR);
  fp = fopen(path, "w");
  if(!fp) { perror(path); return; }

  fprintf(fp, "=== RAW KERNEL STRUCT DUMPS (pid %d) ===\n\n", pid);

  /* Raw ucred dump */
  {
    intptr_t ucred_addr = kernel_get_proc_ucred(pid);
    if(ucred_addr) {
      uint8_t ucred_raw[0x100];
      memset(ucred_raw, 0, sizeof(ucred_raw));
      if(!kernel_copyout(ucred_addr, ucred_raw, sizeof(ucred_raw))) {
        fprintf(fp, "--- RAW UCRED (0x100 bytes @ 0x%lx) ---\n", ucred_addr);
        fprintf(fp, "  known fields:\n");
        fprintf(fp, "    +0x00: cr_ref       = 0x%08x\n", *(uint32_t*)&ucred_raw[0x00]);
        fprintf(fp, "    +0x04: cr_uid       = %d\n", *(uint32_t*)&ucred_raw[0x04]);
        fprintf(fp, "    +0x08: cr_ruid      = %d\n", *(uint32_t*)&ucred_raw[0x08]);
        fprintf(fp, "    +0x0C: cr_svuid     = %d\n", *(uint32_t*)&ucred_raw[0x0C]);
        fprintf(fp, "    +0x10: cr_ngroups   = %d\n", *(uint32_t*)&ucred_raw[0x10]);
        fprintf(fp, "    +0x14: cr_rgid      = %d\n", *(uint32_t*)&ucred_raw[0x14]);
        fprintf(fp, "    +0x18: cr_svgid     = %d\n", *(uint32_t*)&ucred_raw[0x18]);
        fprintf(fp, "    +0x30: cr_prison    = 0x%016lx\n", *(uint64_t*)&ucred_raw[0x30]);
        fprintf(fp, "    +0x58: sceAuthID    = 0x%016lx\n", *(uint64_t*)&ucred_raw[0x58]);
        fprintf(fp, "    +0x60: sceCaps      = ");
        for(int i=0;i<16;i++) fprintf(fp,"%02x",ucred_raw[0x60+i]);
        fprintf(fp, "\n    +0x80: sceAttrs     = ");
        for(int i=0;i<32;i++) fprintf(fp,"%02x",ucred_raw[0x80+i]);
        fprintf(fp, "\n\n  full hex:\n");
        hexdump(fp, ucred_raw, sizeof(ucred_raw), ucred_addr);
        fprintf(fp, "\n");
      }
    }
  }

  /* Raw proc dump */
  {
    intptr_t proc_addr = kernel_get_proc(pid);
    if(proc_addr) {
      uint8_t proc_raw[0x300];
      memset(proc_raw, 0, sizeof(proc_raw));
      if(!kernel_copyout(proc_addr, proc_raw, sizeof(proc_raw))) {
        fprintf(fp, "--- RAW PROC (0x300 bytes @ 0x%lx) ---\n", proc_addr);
        fprintf(fp, "  known fields:\n");
        fprintf(fp, "    +0x00: p_list.next  = 0x%016lx\n", *(uint64_t*)&proc_raw[0x00]);
        fprintf(fp, "    +0x40: p_ucred      = 0x%016lx\n", *(uint64_t*)&proc_raw[0x40]);
        fprintf(fp, "    +0x48: p_fd         = 0x%016lx\n", *(uint64_t*)&proc_raw[0x48]);
        fprintf(fp, "    +0xBC: p_pid        = %d\n", *(int32_t*)&proc_raw[0xBC]);
        fprintf(fp, "    +0x200:p_vmspace    = 0x%016lx\n", *(uint64_t*)&proc_raw[0x200]);
        fprintf(fp, "\n  full hex:\n");
        hexdump(fp, proc_raw, sizeof(proc_raw), proc_addr);
        fprintf(fp, "\n");
      }
    }
  }

  /* Raw filedesc dump */
  {
    intptr_t fd_addr = kernel_get_proc_filedesc(pid);
    if(fd_addr) {
      uint8_t fd_raw[0x80];
      memset(fd_raw, 0, sizeof(fd_raw));
      if(!kernel_copyout(fd_addr, fd_raw, sizeof(fd_raw))) {
        fprintf(fp, "--- RAW FILEDESC (0x80 bytes @ 0x%lx) ---\n", fd_addr);
        fprintf(fp, "  known fields:\n");
        fprintf(fp, "    +0x10: fd_rdir      = 0x%016lx\n", *(uint64_t*)&fd_raw[0x10]);
        fprintf(fp, "    +0x18: fd_jdir      = 0x%016lx\n", *(uint64_t*)&fd_raw[0x18]);
        fprintf(fp, "\n  full hex:\n");
        hexdump(fp, fd_raw, sizeof(fd_raw), fd_addr);
        fprintf(fp, "\n");
      }
    }
  }

  /* Vmspace + pmap dump */
  {
    intptr_t proc_addr = kernel_get_proc(pid);
    if(proc_addr) {
      uint64_t vmspace = 0;
      if(!kernel_copyout(proc_addr + KERNEL_OFFSET_PROC_P_VMSPACE, &vmspace, 8) && vmspace) {
        uint8_t vs_raw[0x300];
        memset(vs_raw, 0, sizeof(vs_raw));
        if(!kernel_copyout(vmspace, vs_raw, sizeof(vs_raw))) {
          fprintf(fp, "--- RAW VMSPACE (0x300 bytes @ 0x%lx) ---\n", vmspace);
          fprintf(fp, "  known fields:\n");
          fprintf(fp, "    +0x%lx: vm_pmap   (pmap struct follows)\n", KERNEL_OFFSET_VMSPACE_VM_PMAP);
          fprintf(fp, "    +0x%lx: p_root    = 0x%016lx\n",
                  KERNEL_OFFSET_VMSPACE_P_ROOT,
                  *(uint64_t*)&vs_raw[KERNEL_OFFSET_VMSPACE_P_ROOT]);
          /* pmap fields: cr3 at pmap+0x28, pml4 at pmap+0x20 */
          size_t pmap_off = KERNEL_OFFSET_VMSPACE_VM_PMAP;
          if(pmap_off + 0x30 < sizeof(vs_raw)) {
            fprintf(fp, "    pmap+0x20: pm_pml4u = 0x%016lx\n",
                    *(uint64_t*)&vs_raw[pmap_off + 0x20]);
            fprintf(fp, "    pmap+0x28: pm_cr3   = 0x%016lx\n",
                    *(uint64_t*)&vs_raw[pmap_off + 0x28]);
          }
          fprintf(fp, "\n  full hex:\n");
          hexdump(fp, vs_raw, sizeof(vs_raw), vmspace);
          fprintf(fp, "\n");
        }
      }
    }
  }

  /* PRISON0 struct dump */
  {
    if(KERNEL_ADDRESS_PRISON0) {
      uint8_t prison_raw[0x100];
      memset(prison_raw, 0, sizeof(prison_raw));
      if(!kernel_copyout(KERNEL_ADDRESS_PRISON0, prison_raw, sizeof(prison_raw))) {
        fprintf(fp, "--- RAW PRISON0 (0x100 bytes @ 0x%lx) ---\n", KERNEL_ADDRESS_PRISON0);
        fprintf(fp, "  full hex:\n");
        hexdump(fp, prison_raw, sizeof(prison_raw), KERNEL_ADDRESS_PRISON0);
        fprintf(fp, "\n");
      }
    }
  }

  /* Root vnode dump */
  {
    intptr_t rvn = kernel_get_root_vnode();
    if(rvn) {
      uint8_t vn_raw[0x100];
      memset(vn_raw, 0, sizeof(vn_raw));
      if(!kernel_copyout(rvn, vn_raw, sizeof(vn_raw))) {
        fprintf(fp, "--- RAW ROOT VNODE (0x100 bytes @ 0x%lx) ---\n", rvn);
        hexdump(fp, vn_raw, sizeof(vn_raw), rvn);
        fprintf(fp, "\n");
      }
    }
  }

  /* IOMMU softc dump */
  {
    if(KERNEL_ADDRESS_IOMMU_SOFTC) {
      uint8_t iommu_raw[0xC0];
      memset(iommu_raw, 0, sizeof(iommu_raw));
      if(!kernel_copyout(KERNEL_ADDRESS_IOMMU_SOFTC, iommu_raw, sizeof(iommu_raw))) {
        fprintf(fp, "--- RAW IOMMU SOFTC (0xC0 bytes @ 0x%lx) ---\n",
                KERNEL_ADDRESS_IOMMU_SOFTC);
        fprintf(fp, "  known fields:\n");
        fprintf(fp, "    +0x80: cb3_ptr   = 0x%016lx\n", *(uint64_t*)&iommu_raw[0x80]);
        fprintf(fp, "    +0x88: cb3_index = 0x%016lx\n", *(uint64_t*)&iommu_raw[0x88]);
        fprintf(fp, "\n  full hex:\n");
        hexdump(fp, iommu_raw, sizeof(iommu_raw), KERNEL_ADDRESS_IOMMU_SOFTC);
        fprintf(fp, "\n");
      }
    }
  }

  fclose(fp);
  printf("wrote %s\n", path);
}

/* ========== PER-PROCESS FLAGS ========== */
static void
write_all_proc_flags(void) {
  FILE* fp;
  char path[256];
  int mib[4] = {1, 14, 8, 0};
  size_t buf_size = 0;
  uint8_t *buf;

  snprintf(path, sizeof(path), "%s/all_proc_flags.txt", OUT_DIR);
  fp = fopen(path, "w");
  if(!fp) { perror(path); return; }

  fprintf(fp, "=== FLAGS FOR ALL RUNNING PROCESSES ===\n\n");
  fprintf(fp, "%-8s %-24s %-18s %-6s %s\n",
          "PID", "NAME", "AUTHID", "UID", "CAPS");
  fprintf(fp, "-------- ------------------------ ------------------ ------ ");
  fprintf(fp, "--------------------------------\n");

  if(sysctl(mib, 4, 0, &buf_size, 0, 0)) { fclose(fp); return; }
  buf = malloc(buf_size);
  if(!buf) { fclose(fp); return; }
  if(sysctl(mib, 4, buf, &buf_size, 0, 0)) { free(buf); fclose(fp); return; }

  for(uint8_t *ptr = buf; ptr < (buf + buf_size);) {
    int ki_structsize = *(int*)ptr;
    pid_t ki_pid = *(pid_t*)&ptr[72];
    char *ki_tdname = (char*)&ptr[447];
    if(ki_structsize <= 0) break;

    uint64_t authid = kernel_get_ucred_authid(ki_pid);
    uid_t uid = kernel_get_ucred_uid(ki_pid);
    uint8_t caps[16] = {0};
    kernel_get_ucred_caps(ki_pid, caps);

    fprintf(fp, "%-8d %-24s 0x%016lx %-6d 0x",
            ki_pid, ki_tdname, authid, uid);
    for(int i = 0; i < 16; i++) fprintf(fp, "%02x", caps[i]);
    fprintf(fp, "\n");

    ptr += ki_structsize;
  }

  free(buf);
  fclose(fp);
  printf("wrote %s\n", path);
}

/* ========== OFFSETS + SYSINFO + HWINFO (combined) ========== */
static void
write_sysinfo(void) {
  FILE* fp;
  char path[256];
  pid_t pid = getpid();

  snprintf(path, sizeof(path), "%s/sysinfo.txt", OUT_DIR);
  fp = fopen(path, "w");
  if(!fp) { perror(path); return; }

  fprintf(fp, "=== SYSTEM INFO & OFFSETS ===\n\n");

  /* offsets */
  fprintf(fp, "--- KERNEL ADDRESSES ---\n");
  fprintf(fp, "TEXT_BASE:         0x%lx\n", KERNEL_ADDRESS_TEXT_BASE);
  fprintf(fp, "DATA_BASE:         0x%lx\n", KERNEL_ADDRESS_DATA_BASE);
  fprintf(fp, "DMAP_BASE:         0x%lx\n", KERNEL_ADDRESS_DMAP_BASE);
  fprintf(fp, "ALLPROC:           0x%lx\n", KERNEL_ADDRESS_ALLPROC);
  fprintf(fp, "PRISON0:           0x%lx\n", KERNEL_ADDRESS_PRISON0);
  fprintf(fp, "ROOTVNODE:         0x%lx\n", KERNEL_ADDRESS_ROOTVNODE);
  fprintf(fp, "SECURITY_FLAGS:    0x%lx\n", KERNEL_ADDRESS_SECURITY_FLAGS);
  fprintf(fp, "UTOKEN_FLAGS:      0x%lx\n", KERNEL_ADDRESS_UTOKEN_FLAGS);
  fprintf(fp, "QA_FLAGS:          0x%lx\n", KERNEL_ADDRESS_QA_FLAGS);
  fprintf(fp, "TARGETID:          0x%lx\n", KERNEL_ADDRESS_TARGETID);
  fprintf(fp, "BUS_DATA_DEVICES:  0x%lx\n", KERNEL_ADDRESS_BUS_DATA_DEVICES);
  fprintf(fp, "IOMMU_SOFTC:       0x%lx\n", KERNEL_ADDRESS_IOMMU_SOFTC);

  fprintf(fp, "\n--- STRUCT OFFSETS ---\n");
  fprintf(fp, "proc.p_ucred:      0x%lx\n", KERNEL_OFFSET_PROC_P_UCRED);
  fprintf(fp, "proc.p_fd:         0x%lx\n", KERNEL_OFFSET_PROC_P_FD);
  fprintf(fp, "proc.p_pid:        0x%lx\n", KERNEL_OFFSET_PROC_P_PID);
  fprintf(fp, "proc.p_vmspace:    0x%lx\n", KERNEL_OFFSET_PROC_P_VMSPACE);
  fprintf(fp, "ucred.cr_uid:      0x%lx\n", KERNEL_OFFSET_UCRED_CR_UID);
  fprintf(fp, "ucred.cr_ruid:     0x%lx\n", KERNEL_OFFSET_UCRED_CR_RUID);
  fprintf(fp, "ucred.cr_svuid:    0x%lx\n", KERNEL_OFFSET_UCRED_CR_SVUID);
  fprintf(fp, "ucred.cr_rgid:     0x%lx\n", KERNEL_OFFSET_UCRED_CR_RGID);
  fprintf(fp, "ucred.cr_svgid:    0x%lx\n", KERNEL_OFFSET_UCRED_CR_SVGID);
  fprintf(fp, "ucred.cr_prison:   0x%lx\n", KERNEL_OFFSET_UCRED_CR_PRISON);
  fprintf(fp, "ucred.cr_sceAuthID:0x%lx\n", KERNEL_OFFSET_UCRED_CR_SCEAUTHID);
  fprintf(fp, "ucred.cr_sceCaps:  0x%lx\n", KERNEL_OFFSET_UCRED_CR_SCECAPS);
  fprintf(fp, "ucred.cr_sceAttrs: 0x%lx\n", KERNEL_OFFSET_UCRED_CR_SCEATTRS);
  fprintf(fp, "filedesc.fd_rdir:  0x%lx\n", KERNEL_OFFSET_FILEDESC_FD_RDIR);
  fprintf(fp, "filedesc.fd_jdir:  0x%lx\n", KERNEL_OFFSET_FILEDESC_FD_JDIR);
  fprintf(fp, "vmspace.vm_pmap:   0x%lx\n", KERNEL_OFFSET_VMSPACE_VM_PMAP);
  fprintf(fp, "vmspace.p_root:    0x%lx\n", KERNEL_OFFSET_VMSPACE_P_ROOT);

  fprintf(fp, "\n--- DELTAS ---\n");
  if(KERNEL_ADDRESS_TEXT_BASE && KERNEL_ADDRESS_DATA_BASE)
    fprintf(fp, "TEXT_TO_DATA:      0x%lx\n", KERNEL_ADDRESS_DATA_BASE - KERNEL_ADDRESS_TEXT_BASE);
  if(KERNEL_ADDRESS_DATA_BASE) {
    fprintf(fp, "DATA_TO_ALLPROC:   0x%lx\n", KERNEL_ADDRESS_ALLPROC - KERNEL_ADDRESS_DATA_BASE);
    fprintf(fp, "DATA_TO_ROOTVNODE: 0x%lx\n", KERNEL_ADDRESS_ROOTVNODE - KERNEL_ADDRESS_DATA_BASE);
    fprintf(fp, "DATA_TO_SECFLAGS:  0x%lx\n", KERNEL_ADDRESS_SECURITY_FLAGS - KERNEL_ADDRESS_DATA_BASE);
    fprintf(fp, "DATA_TO_BUSDATA:   0x%lx\n", KERNEL_ADDRESS_BUS_DATA_DEVICES - KERNEL_ADDRESS_DATA_BASE);
  }

  /* hw + system info */
  fprintf(fp, "\n--- HARDWARE ---\n");
  { char buf[1000]; buf[0]=0; if(!sceKernelGetHwModelName(buf)) fprintf(fp, "model:           %s\n", buf); }
  { int t=0; if(!sceKernelGetCpuTemperature(&t)) fprintf(fp, "cpu_temp:        %d C\n", t); }
  { int t=0; if(!sceKernelGetSocSensorTemperature(0,&t)) fprintf(fp, "soc_temp:        %d C\n", t); }
  { int p=0; if(!sceKernelGetSocPowerConsumption(&p)) fprintf(fp, "soc_power:       %d mW\n", p); }
  fprintf(fp, "cpu_freq:        %ld MHz\n", sceKernelGetCpuFrequency()/(1000*1000));
  fprintf(fp, "tsc_freq:        %ld Hz\n", sceKernelGetTscFrequency());
  fprintf(fp, "current_cpu:     %d\n", sceKernelGetCurrentCpu());
  { unsigned int v=0; if(!sceKernelGetProductCode(&v)) fprintf(fp, "product_code:    0x%08x\n", v); }
  { char buf[256]; buf[0]=0; if(!sceKernelGetProductStr(buf)) fprintf(fp, "product_str:     %s\n", buf); }
  { unsigned int v=0; if(!sceKernelGetBasicProductShape(&v)) fprintf(fp, "product_shape:   0x%x\n", v); }
  { char socid[8]={0}; if(!sceKernelGetMainSocId(socid)) { fprintf(fp, "soc_id:          0x"); for(int i=0;i<8;i++) fprintf(fp,"%02x",(uint8_t)socid[i]); fprintf(fp,"\n"); } }
  { unsigned int v=0; if(!sceKernelGetSubsysId(&v)) fprintf(fp, "subsys_id:       0x%08x\n", v); }
  { size_t dm=0; if(!sceKernelGetDirectMemorySize(&dm)) fprintf(fp, "direct_mem:      %zu MB\n", dm/(1024*1024)); }

  fprintf(fp, "\n--- SOFTWARE ---\n");
  fprintf(fp, "fw_version:      0x%08x\n", kernel_get_fw_version());
  { unsigned int v=0; if(!sceKernelGetProsperoSystemSwVersion(&v)) fprintf(fp, "prospero_sw:     0x%08x\n", v); }
  { char openpsid[16]={0}; if(!sceKernelGetOpenPsId(openpsid)) { fprintf(fp, "openpsid:        0x"); for(int i=0;i<16;i++) fprintf(fp,"%02x",(uint8_t)openpsid[i]); fprintf(fp,"\n"); } }
  { char buf[256]; buf[0]=0; if(!sceKernelGetProcessName(pid,buf)) fprintf(fp, "process_name:    %s\n", buf); }

  /* payload args */
  {
    payload_args_t* args = payload_get_args();
    if(args) {
      fprintf(fp, "\n--- PAYLOAD ARGS ---\n");
      fprintf(fp, "kpipe_addr:      0x%lx\n", args->kpipe_addr);
      fprintf(fp, "kdata_base:      0x%lx\n", args->kdata_base_addr);
    }
  }

  fclose(fp);
  printf("wrote %s\n", path);
}

/* ========== DYNLIB ========== */
static void
write_dynlib(void) {
  FILE* fp;
  char path[256];
  pid_t pid = getpid();
  static const char *libs[] = {
    "libkernel.sprx", "libkernel_sys.sprx", "libSceLibcInternal.sprx",
    "libSceSysmodule.sprx", "libSceSystemService.sprx", "libSceNet.sprx",
    "libSceNetCtl.sprx", "libScePad.sprx", "libSceVideoOut.sprx",
    "libSceAudioOut.sprx", "libSceGnmDriver.sprx", "libSceUserService.sprx",
    "libSceHttp.sprx", "libSceSsl.sprx", "libSceRandom.sprx",
    "libSceRegMgr.sprx", "libSceIpmi.sprx", "libSceSysCore.sprx",
    "libSceNotification.sprx", NULL
  };

  snprintf(path, sizeof(path), "%s/dynlib.txt", OUT_DIR);
  fp = fopen(path, "w");
  if(!fp) { perror(path); return; }

  fprintf(fp, "=== LOADED LIBRARIES (pid %d) ===\n\n", pid);
  for(int i = 0; libs[i]; i++) {
    uint32_t handle = 0;
    if(!kernel_dynlib_handle(pid, libs[i], &handle)) {
      fprintf(fp, "%s\n", libs[i]);
      fprintf(fp, "  handle:  0x%x\n", handle);
      fprintf(fp, "  mapbase: 0x%lx\n", kernel_dynlib_mapbase_addr(pid, handle));
      fprintf(fp, "  entry:   0x%lx\n", kernel_dynlib_entry_addr(pid, handle));
      fprintf(fp, "  init:    0x%lx\n", kernel_dynlib_init_addr(pid, handle));
      fprintf(fp, "  fini:    0x%lx\n", kernel_dynlib_fini_addr(pid, handle));
      fprintf(fp, "\n");
    }
  }

  fclose(fp);
  printf("wrote %s\n", path);
}

/* ========== PROCLIST ========== */
static void
write_proclist(void) {
  FILE* fp;
  char path[256];
  int mib[4] = {1, 14, 8, 0};
  size_t buf_size = 0;
  uint8_t *buf;

  snprintf(path, sizeof(path), "%s/proclist.txt", OUT_DIR);
  fp = fopen(path, "w");
  if(!fp) { perror(path); return; }

  fprintf(fp, "# running processes\n\n");

  if(sysctl(mib, 4, 0, &buf_size, 0, 0)) { fclose(fp); return; }
  buf = malloc(buf_size);
  if(!buf) { fclose(fp); return; }
  if(sysctl(mib, 4, buf, &buf_size, 0, 0)) { free(buf); fclose(fp); return; }

  for(uint8_t *ptr = buf; ptr < (buf + buf_size);) {
    int ki_structsize = *(int*)ptr;
    pid_t ki_pid = *(pid_t*)&ptr[72];
    char *ki_tdname = (char*)&ptr[447];
    if(ki_structsize <= 0) break;
    fprintf(fp, "%-8d %s\n", ki_pid, ki_tdname);
    ptr += ki_structsize;
  }

  free(buf);
  fclose(fp);
  printf("wrote %s\n", path);
}

/* ========== ENABLE TESTKIT FLAGS ========== */
static void
enable_testkit(void) {
  pid_t pid = getpid();
  FILE* fp;
  char path[256];

  snprintf(path, sizeof(path), "%s/enable_testkit.txt", OUT_DIR);
  fp = fopen(path, "w");
  if(!fp) { perror(path); return; }

  fprintf(fp, "=== ENABLE DEVKIT/TESTKIT FLAGS ===\n\n");

  /* TARGETID, SECURITY_FLAGS, UTOKEN_FLAGS are on a read-only kernel page.
     kernel_setchar() uses pipe-based writes which trigger a page fault panic.
     kernel_iommu_setchar() writes via IOMMU DMA, bypassing CPU page protections. */

  /* 0. SECURITY_FLAGS — enable debug/devkit bits via IOMMU */
  {
    uint8_t sf = kernel_getchar(KERNEL_ADDRESS_SECURITY_FLAGS);
    fprintf(fp, "SECURITY_FLAGS before: 0x%02x\n", sf);

    uint8_t sf_new = sf | (1<<0)|(1<<2)|(1<<3)|(1<<5)|(1<<6)|(1<<7);
    if(kernel_iommu_setchar(KERNEL_ADDRESS_SECURITY_FLAGS, sf_new)) {
      fprintf(fp, "  FAILED (IOMMU write)\n");
      printf("enable_testkit: SECURITY_FLAGS IOMMU write failed\n");
    } else {
      uint8_t sf_after = kernel_getchar(KERNEL_ADDRESS_SECURITY_FLAGS);
      fprintf(fp, "SECURITY_FLAGS after:  0x%02x\n", sf_after);
      fprintf(fp, "  SET OK via IOMMU DMA\n");
      printf("enable_testkit: SECURITY_FLAGS -> 0x%02x\n", sf_after);
    }
    fprintf(fp, "\n");
  }

  /* 0b. UTOKEN_FLAGS — enable all via IOMMU */
  {
    uint8_t ut = kernel_getchar(KERNEL_ADDRESS_UTOKEN_FLAGS);
    fprintf(fp, "UTOKEN_FLAGS before: 0x%02x\n", ut);

    if(kernel_iommu_setchar(KERNEL_ADDRESS_UTOKEN_FLAGS, 0xff)) {
      fprintf(fp, "  FAILED (IOMMU write)\n");
      printf("enable_testkit: UTOKEN_FLAGS IOMMU write failed\n");
    } else {
      uint8_t ut_after = kernel_getchar(KERNEL_ADDRESS_UTOKEN_FLAGS);
      fprintf(fp, "UTOKEN_FLAGS after:  0x%02x\n", ut_after);
      fprintf(fp, "  SET OK via IOMMU DMA\n");
      printf("enable_testkit: UTOKEN_FLAGS -> 0x%02x\n", ut_after);
    }
    fprintf(fp, "\n");
  }

  /* 0c. TARGETID — set to DEVKIT (0x02) for devkit panel via IOMMU */
  {
    uint8_t tid = kernel_getchar(KERNEL_ADDRESS_TARGETID);
    fprintf(fp, "TARGETID before: 0x%02x = %s\n", tid, targetid_name(tid));

    if(kernel_iommu_setchar(KERNEL_ADDRESS_TARGETID, 0x02)) {
      fprintf(fp, "  FAILED (IOMMU write)\n");
      printf("enable_testkit: TARGETID IOMMU write failed\n");
    } else {
      uint8_t tid_after = kernel_getchar(KERNEL_ADDRESS_TARGETID);
      fprintf(fp, "TARGETID after:  0x%02x = %s\n", tid_after, targetid_name(tid_after));
      fprintf(fp, "  SET OK via IOMMU DMA\n");
      printf("enable_testkit: TARGETID -> 0x%02x\n", tid_after);
    }
    fprintf(fp, "\n");
  }

  /* 1. QA FLAGS — enable testkit-relevant bits (safe via SDK function) */
  {
    uint8_t qa[16] = {0};
    kernel_get_qaflags(qa);

    fprintf(fp, "QA_FLAGS before: 0x");
    for(int i = 0; i < 16; i++) fprintf(fp, "%02x", qa[i]);
    fprintf(fp, "\n");

    /* byte 0: INTERNAL_DEV(0), QA_ENABLED(1), ALLOW_DEBUG_MENU(2),
               ALLOW_USB_MASS_STORAGE(5), ALLOW_HOST_FS(6), ALLOW_UPDATE_FROM_USB(7) */
    qa[0] |= (1<<0) | (1<<1) | (1<<2) | (1<<5) | (1<<6) | (1<<7);

    /* byte 1: ALLOW_EXTERNAL_HDD_NO_FORMAT(0), ALLOW_INSTALLATION_FROM_HOST(4) */
    qa[1] |= (1<<0) | (1<<4);

    /* byte 2: ENABLE_TESTKIT_FEATURES(0), ENABLE_NP_ENV_SWITCHING(1) */
    qa[2] |= (1<<0) | (1<<1);

    /* byte 3: ALLOW_SYSTEM_LEVEL_DEBUGGER(2) */
    qa[3] |= (1<<2);

    /* byte 4: WEAKEN_PORT_RESTRICTION(2) */
    qa[4] |= (1<<2);

    if(kernel_set_qaflags(qa)) {
      fprintf(fp, "  FAILED to set QA flags\n");
      printf("enable_testkit: FAILED to set QA flags\n");
    } else {
      fprintf(fp, "QA_FLAGS after:  0x");
      for(int i = 0; i < 16; i++) fprintf(fp, "%02x", qa[i]);
      fprintf(fp, "\n");
      fprintf(fp, "  QA flags SET OK\n");
      printf("enable_testkit: QA flags set\n");
    }
    fprintf(fp, "\n");
  }

  /* SECURITY_FLAGS and UTOKEN_FLAGS: HW-protected, read only */
  {
    uint8_t sf = kernel_getchar(KERNEL_ADDRESS_SECURITY_FLAGS);
    uint8_t ut = kernel_getchar(KERNEL_ADDRESS_UTOKEN_FLAGS);
    fprintf(fp, "SECURITY_FLAGS: 0x%02x (read-only, HW protected)\n", sf);
    fprintf(fp, "UTOKEN_FLAGS:   0x%02x (read-only, HW protected)\n\n", ut);
  }

  /* 2. Elevate current process: uid 0, full caps, full attrs, jailbreak */
  {
    fprintf(fp, "--- PROCESS ELEVATION (pid %d) ---\n", pid);

    /* uid/gid to root */
    kernel_set_ucred_uid(pid, 0);
    kernel_set_ucred_ruid(pid, 0);
    kernel_set_ucred_svuid(pid, 0);
    kernel_set_ucred_rgid(pid, 0);
    kernel_set_ucred_svgid(pid, 0);
    fprintf(fp, "  uid/gid -> 0 (root)\n");

    /* SCE authid: system-level */
    kernel_set_ucred_authid(pid, 0x4800000000010003UL);
    fprintf(fp, "  authid -> 0x4800000000010003 (PROSPERO_OS)\n");

    /* full SCE caps */
    uint8_t fullcaps[16];
    memset(fullcaps, 0xff, sizeof(fullcaps));
    kernel_set_ucred_caps(pid, fullcaps);
    fprintf(fp, "  caps -> all 0xff (full privileges)\n");

    /* full SCE attrs */
    uint8_t fullattrs[32];
    memset(fullattrs, 0xff, sizeof(fullattrs));
    kernel_set_ucred_attrs(pid, fullattrs);
    fprintf(fp, "  attrs -> all 0xff (full attributes)\n");

    /* jailbreak: set rootdir and jaildir to root vnode */
    intptr_t rootvnode = kernel_get_root_vnode();
    if(rootvnode) {
      kernel_set_proc_rootdir(pid, rootvnode);
      kernel_set_proc_jaildir(pid, rootvnode);
      fprintf(fp, "  rootdir/jaildir -> root vnode (0x%lx)\n", rootvnode);
    }

    /* escape prison: set to prison0 */
    if(KERNEL_ADDRESS_PRISON0) {
      kernel_set_ucred_prison(pid, KERNEL_ADDRESS_PRISON0);
      fprintf(fp, "  prison -> prison0 (0x%lx)\n", KERNEL_ADDRESS_PRISON0);
    }

    fprintf(fp, "  PROCESS ELEVATED OK\n");
    printf("enable_testkit: process elevated to root + full privs\n");
    fprintf(fp, "\n");
  }

  /* 5. Elevate SceShellUI so the settings app shows the devkit panel */
  {
    int mib[4] = {1, 14, 8, 0};
    size_t buf_size;
    uint8_t *buf;
    pid_t shell_pid = -1;
    pid_t mypid = getpid();

    fprintf(fp, "--- SHELLUI ELEVATION ---\n");

    if(!sysctl(mib, 4, 0, &buf_size, 0, 0) && (buf = malloc(buf_size))) {
      if(!sysctl(mib, 4, buf, &buf_size, 0, 0)) {
        for(uint8_t *ptr = buf; ptr < (buf + buf_size);) {
          int ki_structsize = *(int*)ptr;
          pid_t ki_pid = *(pid_t*)&ptr[72];
          char *ki_tdname = (char*)&ptr[447];
          ptr += ki_structsize;
          if(ki_pid != mypid && !strcmp(ki_tdname, "SceShellUI")) {
            shell_pid = ki_pid;
          }
        }
      }
      free(buf);
    }

    if(shell_pid > 0) {
      fprintf(fp, "  found SceShellUI pid %d\n", shell_pid);

      kernel_set_ucred_authid(shell_pid, 0x4800000000010003UL);
      uint8_t fc[16]; memset(fc, 0xff, sizeof(fc));
      kernel_set_ucred_caps(shell_pid, fc);
      uint8_t fa[32]; memset(fa, 0xff, sizeof(fa));
      kernel_set_ucred_attrs(shell_pid, fa);

      fprintf(fp, "  SceShellUI: authid + caps + attrs elevated\n");
      printf("enable_testkit: SceShellUI (pid %d) elevated\n", shell_pid);
    } else {
      fprintf(fp, "  SceShellUI not found\n");
      printf("enable_testkit: SceShellUI not found\n");
    }
    fprintf(fp, "\n");
  }

  /* 4. Check what the system thinks we are now */
  {
    fprintf(fp, "--- DEVKIT DETECTION ---\n");
    fprintf(fp, "  sceKernelIsDevKit:         %d\n", sceKernelIsDevKit());
    fprintf(fp, "  sceKernelIsTestKit:        %d\n", sceKernelIsTestKit());
    fprintf(fp, "  sceKernelIsCEX:            %d\n", sceKernelIsCEX());
    fprintf(fp, "  sceKernelIsGenuineDevKit:  %d\n", sceKernelIsGenuineDevKit());
    fprintf(fp, "  sceKernelIsGenuineTestKit: %d\n", sceKernelIsGenuineTestKit());
    printf("enable_testkit: isDevKit=%d isTestKit=%d isCEX=%d\n",
           sceKernelIsDevKit(), sceKernelIsTestKit(), sceKernelIsCEX());
    fprintf(fp, "\n");
  }

  fclose(fp);
  printf("wrote %s\n", path);
}

/* ========== REGISTRY APPROACH: DEVKIT PANEL ========== */
static void
try_registry_devkit_panel(void) {
  FILE* fp;
  char path[256];

  snprintf(path, sizeof(path), "%s/registry_devkit.txt", OUT_DIR);
  fp = fopen(path, "w");
  if(!fp) { perror(path); return; }

  fprintf(fp, "=== REGISTRY APPROACH: DEVKIT PANEL ===\n\n");
  printf("registry: probing devkit panel keys...\n");

  /* read all interesting keys first */
  struct { unsigned int key; const char *name; } int_keys[] = {
    { REGKEY_DEVENV_TOOL_host_overlay,         "DEVENV_TOOL_host_overlay" },
    { REGKEY_DEVENV_TOOL_shell_debug,          "DEVENV_TOOL_shell_debug" },
    { REGKEY_DEVENV_TOOL_compositor_dbg,       "DEVENV_TOOL_compositor_dbg" },
    { REGKEY_DEVENV_TOOL_qaflag_masq,          "DEVENV_TOOL_qaflag_masq" },
    { REGKEY_DEVENV_TOOL_trc_notify,           "DEVENV_TOOL_trc_notify" },
    { REGKEY_DEVENV_TOOL_trc_notify_number,    "DEVENV_TOOL_trc_notify_number" },
    { REGKEY_DEVENV_TOOL_SHELLUI_debug_menu,   "DEVENV_TOOL_SHELLUI_debug_menu" },
    { REGKEY_DEVENV_TOOL_SHELLUI_disp_titleid, "DEVENV_TOOL_SHELLUI_disp_titleid" },
    { REGKEY_DEVENV_TOOL_SHELLUI_content_info, "DEVENV_TOOL_SHELLUI_content_info" },
    { REGKEY_SYSTEM_SPECIFIC_show_mode,        "SYSTEM_SPECIFIC_show_mode" },
    { REGKEY_SYSTEM_language,                  "SYSTEM_language (reference)" },
  };
  int nkeys = sizeof(int_keys) / sizeof(int_keys[0]);

  fprintf(fp, "--- CURRENT VALUES ---\n");
  for(int i = 0; i < nkeys; i++) {
    int val = -1;
    int err = sceRegMgrGetInt(int_keys[i].key, &val);
    fprintf(fp, "  %-40s [0x%08x] = ", int_keys[i].name, int_keys[i].key);
    if(err)
      fprintf(fp, "ERR 0x%08x\n", err);
    else
      fprintf(fp, "%d (0x%x)\n", val, val);
    printf("registry: %s = %s%d\n", int_keys[i].name,
           err ? "ERR " : "", err ? err : val);
  }

  /* read devkitname string */
  {
    char devkitname[256] = {0};
    int err = sceRegMgrGetStr(REGKEY_DEVENV_HOST_devkitname, devkitname, sizeof(devkitname));
    fprintf(fp, "  %-40s [0x%08x] = ", "DEVENV_HOST_devkitname", REGKEY_DEVENV_HOST_devkitname);
    if(err)
      fprintf(fp, "ERR 0x%08x\n", err);
    else
      fprintf(fp, "\"%s\"\n", devkitname);
    printf("registry: devkitname = %s\n", err ? "(error)" : devkitname);
  }
  fprintf(fp, "\n");

  /* now try setting the devkit panel keys */
  fprintf(fp, "--- SETTING DEVKIT PANEL KEYS ---\n");

  struct { unsigned int key; const char *name; int value; } set_keys[] = {
    { REGKEY_DEVENV_TOOL_host_overlay,         "host_overlay",      1 },
    { REGKEY_DEVENV_TOOL_shell_debug,          "shell_debug",       1 },
    { REGKEY_DEVENV_TOOL_SHELLUI_debug_menu,   "SHELLUI_debug_menu",1 },
    { REGKEY_DEVENV_TOOL_SHELLUI_disp_titleid, "SHELLUI_disp_titleid",1 },
    { REGKEY_DEVENV_TOOL_SHELLUI_content_info, "SHELLUI_content_info",1 },
    { REGKEY_DEVENV_TOOL_trc_notify,           "trc_notify",        1 },
    { REGKEY_DEVENV_TOOL_compositor_dbg,       "compositor_dbg",    1 },
    { REGKEY_SYSTEM_SPECIFIC_show_mode,        "show_mode",         1 },
  };
  int nset = sizeof(set_keys) / sizeof(set_keys[0]);

  for(int i = 0; i < nset; i++) {
    int err = sceRegMgrSetInt(set_keys[i].key, set_keys[i].value);
    fprintf(fp, "  SET %-30s -> %d : %s (0x%08x)\n",
            set_keys[i].name, set_keys[i].value,
            err ? "FAILED" : "OK", err);
    printf("registry: SET %s -> %d : %s\n",
           set_keys[i].name, set_keys[i].value,
           err ? "FAILED" : "OK");
  }
  fprintf(fp, "\n");

  /* verify by reading back */
  fprintf(fp, "--- READBACK AFTER SET ---\n");
  for(int i = 0; i < nset; i++) {
    int val = -1;
    int err = sceRegMgrGetInt(set_keys[i].key, &val);
    fprintf(fp, "  %-30s = ", set_keys[i].name);
    if(err)
      fprintf(fp, "ERR 0x%08x\n", err);
    else
      fprintf(fp, "%d (0x%x)\n", val, val);
  }
  fprintf(fp, "\n");

  fprintf(fp, "NOTE: shell restart (kill SceShellUI) may be needed for overlay to appear.\n");
  fprintf(fp, "The devkit panel overlay shows target name, IP, and FW version on the home screen.\n");

  fclose(fp);
  printf("wrote %s\n", path);
}

int
main(void) {
  mkdir(OUT_DIR, 0777);

  /* enable testkit flags first, then dump everything (so dumps reflect new state) */
  enable_testkit();

  /* try registry approach for devkit panel overlay */
  try_registry_devkit_panel();

  write_flags();
  write_struct_dumps();
  write_all_proc_flags();
  write_sysinfo();
  write_dynlib();
  write_proclist();

  /* print flags.txt to stdout */
  {
    char path[256];
    snprintf(path, sizeof(path), "%s/flags.txt", OUT_DIR);
    FILE* rd = fopen(path, "r");
    if(rd) {
      char line[512];
      while(fgets(line, sizeof(line), rd))
        printf("%s", line);
      fclose(rd);
    }
  }

  printf("\ndone — all files in " OUT_DIR "\n");
  notify("testpayload: testkit enabled + data dumped to " OUT_DIR);

  return 0;
}
