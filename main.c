/* Minimal PS5 payload: dumps the SDK's kernel offsets/addresses for the
 * running firmware to /data/testpayload/offsets.txt, shows a notification,
 * and logs to stdout. Build with the ps5-payload-sdk
 * (https://github.com/ps5-payload-dev/sdk). */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ps5/kernel.h>

#define OUT_DIR  "/data/testpayload"
#define OUT_FILE OUT_DIR "/offsets.txt"

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

int
main(void) {
  FILE* fp;
  uint32_t fw = kernel_get_fw_version();

  mkdir(OUT_DIR, 0777);

  fp = fopen(OUT_FILE, "w");
  if(!fp) {
    perror("fopen");
    notify("testpayload: failed to open " OUT_FILE);
    return 1;
  }

  fprintf(fp, "fw_version: 0x%08x\n\n", fw);

  fprintf(fp, "# absolute kernel pointers\n");
  fprintf(fp, "KERNEL_ADDRESS_TEXT_BASE        0x%lx\n", KERNEL_ADDRESS_TEXT_BASE);
  fprintf(fp, "KERNEL_ADDRESS_DATA_BASE        0x%lx\n", KERNEL_ADDRESS_DATA_BASE);
  fprintf(fp, "KERNEL_ADDRESS_ALLPROC          0x%lx\n", KERNEL_ADDRESS_ALLPROC);
  fprintf(fp, "KERNEL_ADDRESS_PRISON0          0x%lx\n", KERNEL_ADDRESS_PRISON0);
  fprintf(fp, "KERNEL_ADDRESS_ROOTVNODE        0x%lx\n", KERNEL_ADDRESS_ROOTVNODE);
  fprintf(fp, "KERNEL_ADDRESS_SECURITY_FLAGS   0x%lx\n", KERNEL_ADDRESS_SECURITY_FLAGS);
  fprintf(fp, "KERNEL_ADDRESS_UTOKEN_FLAGS     0x%lx\n", KERNEL_ADDRESS_UTOKEN_FLAGS);
  fprintf(fp, "KERNEL_ADDRESS_QA_FLAGS         0x%lx\n", KERNEL_ADDRESS_QA_FLAGS);
  fprintf(fp, "KERNEL_ADDRESS_TARGETID         0x%lx\n", KERNEL_ADDRESS_TARGETID);
  fprintf(fp, "KERNEL_ADDRESS_BUS_DATA_DEVICES 0x%lx\n", KERNEL_ADDRESS_BUS_DATA_DEVICES);

  fprintf(fp, "\n# struct proc field offsets\n");
  fprintf(fp, "KERNEL_OFFSET_PROC_P_UCRED      0x%lx\n", KERNEL_OFFSET_PROC_P_UCRED);
  fprintf(fp, "KERNEL_OFFSET_PROC_P_FD         0x%lx\n", KERNEL_OFFSET_PROC_P_FD);
  fprintf(fp, "KERNEL_OFFSET_PROC_P_PID        0x%lx\n", KERNEL_OFFSET_PROC_P_PID);
  fprintf(fp, "KERNEL_OFFSET_PROC_P_VMSPACE    0x%lx\n", KERNEL_OFFSET_PROC_P_VMSPACE);

  fprintf(fp, "\n# struct ucred field offsets\n");
  fprintf(fp, "KERNEL_OFFSET_UCRED_CR_UID      0x%lx\n", KERNEL_OFFSET_UCRED_CR_UID);
  fprintf(fp, "KERNEL_OFFSET_UCRED_CR_RUID     0x%lx\n", KERNEL_OFFSET_UCRED_CR_RUID);
  fprintf(fp, "KERNEL_OFFSET_UCRED_CR_SVUID    0x%lx\n", KERNEL_OFFSET_UCRED_CR_SVUID);
  fprintf(fp, "KERNEL_OFFSET_UCRED_CR_RGID     0x%lx\n", KERNEL_OFFSET_UCRED_CR_RGID);
  fprintf(fp, "KERNEL_OFFSET_UCRED_CR_SCEAUTHID 0x%lx\n", KERNEL_OFFSET_UCRED_CR_SCEAUTHID);
  fprintf(fp, "KERNEL_OFFSET_UCRED_CR_SCECAPS  0x%lx\n", KERNEL_OFFSET_UCRED_CR_SCECAPS);
  fprintf(fp, "KERNEL_OFFSET_UCRED_CR_SCEATTRS 0x%lx\n", KERNEL_OFFSET_UCRED_CR_SCEATTRS);

  fprintf(fp, "\n# struct filedesc field offsets\n");
  fprintf(fp, "KERNEL_OFFSET_FILEDESC_FD_RDIR  0x%lx\n", KERNEL_OFFSET_FILEDESC_FD_RDIR);
  fprintf(fp, "KERNEL_OFFSET_FILEDESC_FD_JDIR  0x%lx\n", KERNEL_OFFSET_FILEDESC_FD_JDIR);

  fprintf(fp, "\n# struct vmspace field offsets\n");
  fprintf(fp, "KERNEL_OFFSET_VMSPACE_VM_PMAP   0x%lx\n", KERNEL_OFFSET_VMSPACE_VM_PMAP);

  fclose(fp);

  printf("wrote kernel offsets for fw 0x%08x to " OUT_FILE "\n", fw);
  notify("testpayload: wrote kernel offsets to " OUT_FILE);

  return 0;
}
