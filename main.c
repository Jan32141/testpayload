/* PS5 payload: comprehensive offset and system info dump to /data/testpayload/
 * Build with the ps5-payload-sdk. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
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
int  sceKernelGetHwSerialNumber(char *);
long sceKernelGetCpuFrequency(void);
int  sceKernelGetCpuTemperature(int *);
int  sceKernelGetSocSensorTemperature(int, int *);
int  sceKernelGetSocPowerConsumption(int *);

/* system info */
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
int  sceKernelGetGPO(unsigned int *);
int  sceKernelGetSystemSwVersion(char *);
int  sceKernelGetUpdVersion(char *);

/* dynlib */
int  sceKernelGetModuleList(int *, size_t);
int  sceKernelGetModuleInfo(int, void *);

/* ---- helpers ---- */
static void
notify(const char* msg) {
  notify_request_t req;
  memset(&req, 0, sizeof(req));
  strncpy(req.message, msg, sizeof(req.message) - 1);
  sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

static void
hex_string(const uint8_t* bin, char* hex, size_t len) {
  hex[0] = '0'; hex[1] = 'x';
  for(size_t i = 0; i < len; i++)
    sprintf(&hex[i*2 + 2], "%02x", bin[i]);
  hex[len*2 + 2] = '\0';
}

/* ---- offset dump ---- */
static void
write_offsets(void) {
  FILE* fp;
  char path[256];
  uint32_t fw = kernel_get_fw_version();

  snprintf(path, sizeof(path), "%s/offsets.txt", OUT_DIR);
  fp = fopen(path, "w");
  if(!fp) { perror(path); return; }

  fprintf(fp, "fw_version: 0x%08x\n\n", fw);

  fprintf(fp, "# absolute kernel addresses\n");
  fprintf(fp, "KERNEL_ADDRESS_TEXT_BASE         0x%lx\n", KERNEL_ADDRESS_TEXT_BASE);
  fprintf(fp, "KERNEL_ADDRESS_DATA_BASE         0x%lx\n", KERNEL_ADDRESS_DATA_BASE);
  fprintf(fp, "KERNEL_ADDRESS_DMAP_BASE         0x%lx\n", KERNEL_ADDRESS_DMAP_BASE);
  fprintf(fp, "KERNEL_ADDRESS_ALLPROC           0x%lx\n", KERNEL_ADDRESS_ALLPROC);
  fprintf(fp, "KERNEL_ADDRESS_PRISON0           0x%lx\n", KERNEL_ADDRESS_PRISON0);
  fprintf(fp, "KERNEL_ADDRESS_ROOTVNODE         0x%lx\n", KERNEL_ADDRESS_ROOTVNODE);
  fprintf(fp, "KERNEL_ADDRESS_SECURITY_FLAGS    0x%lx\n", KERNEL_ADDRESS_SECURITY_FLAGS);
  fprintf(fp, "KERNEL_ADDRESS_UTOKEN_FLAGS      0x%lx\n", KERNEL_ADDRESS_UTOKEN_FLAGS);
  fprintf(fp, "KERNEL_ADDRESS_QA_FLAGS          0x%lx\n", KERNEL_ADDRESS_QA_FLAGS);
  fprintf(fp, "KERNEL_ADDRESS_TARGETID          0x%lx\n", KERNEL_ADDRESS_TARGETID);
  fprintf(fp, "KERNEL_ADDRESS_BUS_DATA_DEVICES  0x%lx\n", KERNEL_ADDRESS_BUS_DATA_DEVICES);
  fprintf(fp, "KERNEL_ADDRESS_IOMMU_SOFTC       0x%lx\n", KERNEL_ADDRESS_IOMMU_SOFTC);

  fprintf(fp, "\n# struct proc field offsets\n");
  fprintf(fp, "KERNEL_OFFSET_PROC_P_UCRED       0x%lx\n", KERNEL_OFFSET_PROC_P_UCRED);
  fprintf(fp, "KERNEL_OFFSET_PROC_P_FD          0x%lx\n", KERNEL_OFFSET_PROC_P_FD);
  fprintf(fp, "KERNEL_OFFSET_PROC_P_PID         0x%lx\n", KERNEL_OFFSET_PROC_P_PID);
  fprintf(fp, "KERNEL_OFFSET_PROC_P_VMSPACE     0x%lx\n", KERNEL_OFFSET_PROC_P_VMSPACE);

  fprintf(fp, "\n# struct ucred field offsets\n");
  fprintf(fp, "KERNEL_OFFSET_UCRED_CR_UID       0x%lx\n", KERNEL_OFFSET_UCRED_CR_UID);
  fprintf(fp, "KERNEL_OFFSET_UCRED_CR_RUID      0x%lx\n", KERNEL_OFFSET_UCRED_CR_RUID);
  fprintf(fp, "KERNEL_OFFSET_UCRED_CR_SVUID     0x%lx\n", KERNEL_OFFSET_UCRED_CR_SVUID);
  fprintf(fp, "KERNEL_OFFSET_UCRED_CR_RGID      0x%lx\n", KERNEL_OFFSET_UCRED_CR_RGID);
  fprintf(fp, "KERNEL_OFFSET_UCRED_CR_SVGID     0x%lx\n", KERNEL_OFFSET_UCRED_CR_SVGID);
  fprintf(fp, "KERNEL_OFFSET_UCRED_CR_PRISON    0x%lx\n", KERNEL_OFFSET_UCRED_CR_PRISON);
  fprintf(fp, "KERNEL_OFFSET_UCRED_CR_SCEAUTHID 0x%lx\n", KERNEL_OFFSET_UCRED_CR_SCEAUTHID);
  fprintf(fp, "KERNEL_OFFSET_UCRED_CR_SCECAPS   0x%lx\n", KERNEL_OFFSET_UCRED_CR_SCECAPS);
  fprintf(fp, "KERNEL_OFFSET_UCRED_CR_SCEATTRS  0x%lx\n", KERNEL_OFFSET_UCRED_CR_SCEATTRS);

  fprintf(fp, "\n# struct filedesc field offsets\n");
  fprintf(fp, "KERNEL_OFFSET_FILEDESC_FD_RDIR   0x%lx\n", KERNEL_OFFSET_FILEDESC_FD_RDIR);
  fprintf(fp, "KERNEL_OFFSET_FILEDESC_FD_JDIR   0x%lx\n", KERNEL_OFFSET_FILEDESC_FD_JDIR);

  fprintf(fp, "\n# struct vmspace field offsets\n");
  fprintf(fp, "KERNEL_OFFSET_VMSPACE_VM_PMAP    0x%lx\n", KERNEL_OFFSET_VMSPACE_VM_PMAP);
  fprintf(fp, "KERNEL_OFFSET_VMSPACE_P_ROOT     0x%lx\n", KERNEL_OFFSET_VMSPACE_P_ROOT);

  /* computed offsets: SECURITY_FLAGS relative fields */
  fprintf(fp, "\n# computed (relative to SECURITY_FLAGS)\n");
  fprintf(fp, "TARGETID_OFFSET_FROM_SECFLAGS    0x09\n");
  fprintf(fp, "QA_FLAGS_OFFSET_FROM_SECFLAGS    0x24\n");
  fprintf(fp, "UTOKEN_FLAGS_OFFSET_FROM_SECFLAGS 0x8c\n");

  /* text-to-data delta */
  fprintf(fp, "\n# deltas\n");
  if(KERNEL_ADDRESS_TEXT_BASE && KERNEL_ADDRESS_DATA_BASE) {
    fprintf(fp, "TEXT_TO_DATA_DELTA               0x%lx\n",
            KERNEL_ADDRESS_DATA_BASE - KERNEL_ADDRESS_TEXT_BASE);
  }
  if(KERNEL_ADDRESS_DATA_BASE && KERNEL_ADDRESS_ALLPROC) {
    fprintf(fp, "DATA_TO_ALLPROC_DELTA            0x%lx\n",
            KERNEL_ADDRESS_ALLPROC - KERNEL_ADDRESS_DATA_BASE);
  }
  if(KERNEL_ADDRESS_DATA_BASE && KERNEL_ADDRESS_ROOTVNODE) {
    fprintf(fp, "DATA_TO_ROOTVNODE_DELTA          0x%lx\n",
            KERNEL_ADDRESS_ROOTVNODE - KERNEL_ADDRESS_DATA_BASE);
  }
  if(KERNEL_ADDRESS_DATA_BASE && KERNEL_ADDRESS_SECURITY_FLAGS) {
    fprintf(fp, "DATA_TO_SECFLAGS_DELTA           0x%lx\n",
            KERNEL_ADDRESS_SECURITY_FLAGS - KERNEL_ADDRESS_DATA_BASE);
  }
  if(KERNEL_ADDRESS_DATA_BASE && KERNEL_ADDRESS_BUS_DATA_DEVICES) {
    fprintf(fp, "DATA_TO_BUS_DATA_DEVICES_DELTA   0x%lx\n",
            KERNEL_ADDRESS_BUS_DATA_DEVICES - KERNEL_ADDRESS_DATA_BASE);
  }

  fclose(fp);
  printf("wrote %s\n", path);
}

/* ---- runtime credential & proc dump ---- */
static void
write_runtime(void) {
  FILE* fp;
  char path[256];
  pid_t pid = getpid();
  uint8_t caps[16] = {0};
  uint8_t attrs[32] = {0};
  uint8_t qaflags[16] = {0};
  char hex[128];
  app_info_t app = {0};

  snprintf(path, sizeof(path), "%s/runtime.txt", OUT_DIR);
  fp = fopen(path, "w");
  if(!fp) { perror(path); return; }

  fprintf(fp, "# runtime values for pid %d\n\n", pid);

  /* firmware & console flags read from kernel memory */
  fprintf(fp, "fw_version:      0x%08x\n", kernel_get_fw_version());
  fprintf(fp, "TARGETID:        0x%02x\n",
          kernel_getchar(KERNEL_ADDRESS_TARGETID));
  fprintf(fp, "SECURITY_FLAGS:  0x%02x\n",
          kernel_getchar(KERNEL_ADDRESS_SECURITY_FLAGS));
  fprintf(fp, "UTOKEN_FLAGS:    0x%02x\n",
          kernel_getchar(KERNEL_ADDRESS_UTOKEN_FLAGS));

  kernel_get_qaflags(qaflags);
  hex_string(qaflags, hex, sizeof(qaflags));
  fprintf(fp, "QA_FLAGS:        %s\n", hex);

  /* ucred info */
  fprintf(fp, "\n# ucred\n");
  fprintf(fp, "uid:             %d\n", kernel_get_ucred_uid(pid));
  fprintf(fp, "ruid:            %d\n", kernel_get_ucred_ruid(pid));
  fprintf(fp, "svuid:           %d\n", kernel_get_ucred_svuid(pid));
  fprintf(fp, "rgid:            %d\n", kernel_get_ucred_rgid(pid));
  fprintf(fp, "svgid:           %d\n", kernel_get_ucred_svgid(pid));
  fprintf(fp, "authid:          0x%016lx\n", kernel_get_ucred_authid(pid));
  fprintf(fp, "prison:          0x%lx\n", kernel_get_ucred_prison(pid));

  kernel_get_ucred_caps(pid, caps);
  hex_string(caps, hex, sizeof(caps));
  fprintf(fp, "caps:            %s\n", hex);

  kernel_get_ucred_attrs(pid, attrs);
  hex_string(attrs, hex, sizeof(attrs));
  fprintf(fp, "attrs:           %s\n", hex);

  /* proc pointers */
  fprintf(fp, "\n# proc\n");
  fprintf(fp, "proc:            0x%lx\n", kernel_get_proc(pid));
  fprintf(fp, "proc_ucred:      0x%lx\n", kernel_get_proc_ucred(pid));
  fprintf(fp, "proc_filedesc:   0x%lx\n", kernel_get_proc_filedesc(pid));
  fprintf(fp, "proc_rootdir:    0x%lx\n", kernel_get_proc_rootdir(pid));
  fprintf(fp, "proc_jaildir:    0x%lx\n", kernel_get_proc_jaildir(pid));
  fprintf(fp, "root_vnode:      0x%lx\n", kernel_get_root_vnode());

  /* app info */
  if(!sceKernelGetAppInfo(pid, &app)) {
    fprintf(fp, "\n# app info\n");
    fprintf(fp, "app_id:          %u\n", app.app_id);
    fprintf(fp, "title_id:        %s\n", app.title_id);
  }

  /* read first 8 bytes at SECURITY_FLAGS for the full flags block */
  {
    uint64_t secflags_qword = 0;
    if(!kernel_copyout(KERNEL_ADDRESS_SECURITY_FLAGS, &secflags_qword, 8)) {
      fprintf(fp, "\n# SECURITY_FLAGS raw qword\n");
      fprintf(fp, "secflags_raw:    0x%016lx\n", secflags_qword);
    }
  }

  fclose(fp);
  printf("wrote %s\n", path);
}

/* ---- hardware info ---- */
static void
write_hwinfo(void) {
  FILE* fp;
  char path[256];
  char buf[1000];
  int temp = 0;
  int power = 0;
  unsigned int val = 0;

  snprintf(path, sizeof(path), "%s/hwinfo.txt", OUT_DIR);
  fp = fopen(path, "w");
  if(!fp) { perror(path); return; }

  fprintf(fp, "# hardware info\n\n");

  buf[0] = '\0';
  if(!sceKernelGetHwModelName(buf))
    fprintf(fp, "model:           %s\n", buf);

  if(!sceKernelGetSocSensorTemperature(0, &temp))
    fprintf(fp, "soc_temp:        %d C\n", temp);

  if(!sceKernelGetCpuTemperature(&temp))
    fprintf(fp, "cpu_temp:        %d C\n", temp);

  fprintf(fp, "cpu_freq:        %ld MHz\n",
          sceKernelGetCpuFrequency() / (1000*1000));

  if(!sceKernelGetSocPowerConsumption(&power))
    fprintf(fp, "soc_power:       %d mW\n", power);

  fprintf(fp, "tsc_freq:        %ld Hz\n", sceKernelGetTscFrequency());
  fprintf(fp, "current_cpu:     %d\n", sceKernelGetCurrentCpu());
  fprintf(fp, "phys_page_size:  %d\n", sceKernelGetPhysPageSize());

  if(!sceKernelGetProductCode(&val))
    fprintf(fp, "product_code:    0x%08x\n", val);

  buf[0] = '\0';
  if(!sceKernelGetProductStr(buf))
    fprintf(fp, "product_str:     %s\n", buf);

  if(!sceKernelGetBasicProductShape(&val))
    fprintf(fp, "product_shape:   0x%x\n", val);

  if(!sceKernelGetSafemode(&val))
    fprintf(fp, "safemode:        %u\n", val);

  if(!sceKernelGetAslrStatus(&val))
    fprintf(fp, "aslr_status:     %u\n", val);

  {
    size_t dmem = 0;
    if(!sceKernelGetDirectMemorySize(&dmem))
      fprintf(fp, "direct_mem_size: %zu bytes (%zu MB)\n", dmem, dmem/(1024*1024));
  }

  {
    char socid[8] = {0};
    char socid_hex[20];
    if(!sceKernelGetMainSocId(socid)) {
      hex_string((uint8_t*)socid, socid_hex, 8);
      fprintf(fp, "main_soc_id:     %s\n", socid_hex);
    }
  }

  if(!sceKernelGetGPI(&val))
    fprintf(fp, "gpi:             0x%08x\n", val);

  if(!sceKernelGetGPO(&val))
    fprintf(fp, "gpo:             0x%08x\n", val);

  fclose(fp);
  printf("wrote %s\n", path);
}

/* ---- payload args from ELF loader ---- */
static void
write_payload_args(void) {
  FILE* fp;
  char path[256];
  payload_args_t* args = payload_get_args();

  if(!args) return;

  snprintf(path, sizeof(path), "%s/payload_args.txt", OUT_DIR);
  fp = fopen(path, "w");
  if(!fp) { perror(path); return; }

  fprintf(fp, "# payload_args_t from ELF loader\n\n");
  fprintf(fp, "kpipe_addr:      0x%lx\n", args->kpipe_addr);
  fprintf(fp, "kdata_base_addr: 0x%lx\n", args->kdata_base_addr);

  fclose(fp);
  printf("wrote %s\n", path);
}

/* ---- system version strings ---- */
static void
write_sysinfo(void) {
  FILE* fp;
  char path[256];
  char buf[256];
  unsigned int ver = 0;

  snprintf(path, sizeof(path), "%s/sysinfo.txt", OUT_DIR);
  fp = fopen(path, "w");
  if(!fp) { perror(path); return; }

  fprintf(fp, "# system info\n\n");

  if(!sceKernelGetProsperoSystemSwVersion(&ver))
    fprintf(fp, "prospero_sw_ver: 0x%08x\n", ver);

  buf[0] = '\0';
  if(!sceKernelGetSystemSwVersion(buf))
    fprintf(fp, "system_sw_ver:   %s\n", buf);

  buf[0] = '\0';
  if(!sceKernelGetUpdVersion(buf))
    fprintf(fp, "upd_version:     %s\n", buf);

  {
    char openpsid[16] = {0};
    char openpsid_hex[40];
    if(!sceKernelGetOpenPsId(openpsid)) {
      hex_string((uint8_t*)openpsid, openpsid_hex, 16);
      fprintf(fp, "open_psid:       %s\n", openpsid_hex);
    }
  }

  {
    unsigned int subsysid = 0;
    if(!sceKernelGetSubsysId(&subsysid))
      fprintf(fp, "subsys_id:       0x%08x\n", subsysid);
  }

  {
    pid_t pid = getpid();
    buf[0] = '\0';
    if(!sceKernelGetProcessName(pid, buf))
      fprintf(fp, "process_name:    %s\n", buf);

    unsigned int ptype = 0;
    if(!sceKernelGetProcessType(pid, &ptype))
      fprintf(fp, "process_type:    0x%x\n", ptype);
  }

  fclose(fp);
  printf("wrote %s\n", path);
}

/* ---- process list via sysctl ---- */
static void
write_proclist(void) {
  FILE* fp;
  char path[256];
  int mib[4] = {1, 14, 8, 0}; /* CTL_KERN, KERN_PROC, KERN_PROC_ALL */
  size_t buf_size = 0;
  uint8_t *buf;

  snprintf(path, sizeof(path), "%s/proclist.txt", OUT_DIR);
  fp = fopen(path, "w");
  if(!fp) { perror(path); return; }

  fprintf(fp, "# running processes\n");
  fprintf(fp, "# pid    name\n\n");

  if(sysctl(mib, 4, 0, &buf_size, 0, 0)) {
    perror("sysctl size");
    fclose(fp);
    return;
  }

  buf = malloc(buf_size);
  if(!buf) {
    fclose(fp);
    return;
  }

  if(sysctl(mib, 4, buf, &buf_size, 0, 0)) {
    perror("sysctl data");
    free(buf);
    fclose(fp);
    return;
  }

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

/* ---- kernel memory region around SECURITY_FLAGS ---- */
static void
write_secflags_region(void) {
  FILE* fp;
  char path[256];
  uint8_t region[256];

  if(!KERNEL_ADDRESS_SECURITY_FLAGS) return;

  snprintf(path, sizeof(path), "%s/secflags_region.txt", OUT_DIR);
  fp = fopen(path, "w");
  if(!fp) { perror(path); return; }

  fprintf(fp, "# 256 bytes starting at SECURITY_FLAGS (0x%lx)\n",
          KERNEL_ADDRESS_SECURITY_FLAGS);
  fprintf(fp, "# contains: security_flags(+0x00), targetid(+0x09),\n");
  fprintf(fp, "#           qa_flags(+0x24), utoken_flags(+0x8c)\n\n");

  memset(region, 0, sizeof(region));
  if(!kernel_copyout(KERNEL_ADDRESS_SECURITY_FLAGS, region, sizeof(region))) {
    for(int i = 0; i < 256; i += 16) {
      fprintf(fp, "%04x: ", i);
      for(int j = 0; j < 16; j++)
        fprintf(fp, "%02x ", region[i+j]);
      fprintf(fp, " ");
      for(int j = 0; j < 16; j++) {
        uint8_t c = region[i+j];
        fprintf(fp, "%c", (c >= 0x20 && c < 0x7f) ? c : '.');
      }
      fprintf(fp, "\n");
    }
  }

  fclose(fp);
  printf("wrote %s\n", path);
}

/* ---- dynlib info for our process ---- */
static void
write_dynlib_info(void) {
  FILE* fp;
  char path[256];
  pid_t pid = getpid();
  /* try a few well-known library names */
  static const char *libs[] = {
    "libkernel.sprx",
    "libkernel_sys.sprx",
    "libSceLibcInternal.sprx",
    "libSceSysmodule.sprx",
    "libSceSystemService.sprx",
    "libSceNet.sprx",
    "libSceNetCtl.sprx",
    "libScePad.sprx",
    "libSceVideoOut.sprx",
    "libSceAudioOut.sprx",
    "libSceGnmDriver.sprx",
    "libSceUserService.sprx",
    NULL
  };

  snprintf(path, sizeof(path), "%s/dynlib.txt", OUT_DIR);
  fp = fopen(path, "w");
  if(!fp) { perror(path); return; }

  fprintf(fp, "# loaded library base addresses (pid %d)\n\n", pid);

  for(int i = 0; libs[i]; i++) {
    uint32_t handle = 0;
    if(!kernel_dynlib_handle(pid, libs[i], &handle)) {
      intptr_t base = kernel_dynlib_mapbase_addr(pid, handle);
      intptr_t entry = kernel_dynlib_entry_addr(pid, handle);
      intptr_t init  = kernel_dynlib_init_addr(pid, handle);
      intptr_t fini  = kernel_dynlib_fini_addr(pid, handle);
      fprintf(fp, "%s\n", libs[i]);
      fprintf(fp, "  handle:  0x%x\n", handle);
      fprintf(fp, "  mapbase: 0x%lx\n", base);
      fprintf(fp, "  entry:   0x%lx\n", entry);
      fprintf(fp, "  init:    0x%lx\n", init);
      fprintf(fp, "  fini:    0x%lx\n", fini);
      fprintf(fp, "\n");
    }
  }

  fclose(fp);
  printf("wrote %s\n", path);
}

int
main(void) {
  mkdir(OUT_DIR, 0777);

  write_offsets();
  write_runtime();
  write_hwinfo();
  write_payload_args();
  write_sysinfo();
  write_proclist();
  write_secflags_region();
  write_dynlib_info();

  printf("done — all files in " OUT_DIR "\n");
  notify("testpayload: wrote all data to " OUT_DIR);

  return 0;
}
