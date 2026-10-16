/* PS5 payload: dumps every SDK-exported kernel offset, address, and
 * runtime value to /data/testpayload/.  Build with the ps5-payload-sdk. */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ps5/kernel.h>
#include <ps5/payload.h>

#define OUT_DIR  "/data/testpayload"

/* ---- CRT-internal symbols not in the public header ---- */
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

/* ---- writers ---- */
static void
write_offsets(void) {
  FILE* fp;
  uint32_t fw = kernel_get_fw_version();
  char path[256];

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

  fclose(fp);
  printf("wrote %s\n", path);
}

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

  /* firmware & console flags */
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

  fclose(fp);
  printf("wrote %s\n", path);
}

static void
write_hwinfo(void) {
  FILE* fp;
  char path[256];
  char buf[1000];
  int temp = 0;

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

  fclose(fp);
  printf("wrote %s\n", path);
}

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

int
main(void) {
  mkdir(OUT_DIR, 0777);

  write_offsets();
  write_runtime();
  write_hwinfo();
  write_payload_args();

  printf("done — all files in " OUT_DIR "\n");
  notify("testpayload: wrote offsets to " OUT_DIR);

  return 0;
}
