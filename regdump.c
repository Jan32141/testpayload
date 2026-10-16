/* Dump PS5 registry: enumerate files, entry counts, and raw data.
 * Requires elevated process (run after enable_testkit or standalone with jailbreak). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ps5/kernel.h>

#define OUT_DIR  "/data/testpayload"

/* registry manager functions */
int sceRegMgrGetInt(unsigned int regId, int *value);
int sceRegMgrSetInt(unsigned int regId, int value);
int sceRegMgrGetStr(unsigned int regId, char *buf, size_t size);
int sceRegMgrGetBin(unsigned int regId, void *buf, size_t size);
int sceRegMgrNonSysGetInt(unsigned int regId, int *value);

int sceRegMgrCntlGetFilesCount(int *count);
int sceRegMgrCntlGetFileName(int index, char *buf, size_t size);
int sceRegMgrToolGetEntryCnt(int *count);
int sceRegMgrToolGetInfo(int index, void *info, size_t size);
int sceRegMgrToolGetUpdateCnt(int *count);
int sceRegMgrDrvGetEntCnt(int *count);
int sceRegMgrDrvGetUpdateCnt(int *count);
int sceRegMgrDrvDataOpen(const char *path, void **handle);
int sceRegMgrDrvDataClose(void *handle);
int sceRegMgrDrvDataCheckGet(void *handle, void *buf, size_t size);
int sceRegMgrToolDataCheckGet(void *handle, void *buf, size_t size);
int sceRegMgrEvtGetCnt(int *count);
int sceRegMgrEvtGetRegId(int index, unsigned int *regId);
int sceRegMgrEvtGetCntForPS4(int *count);
int sceRegMgrEvtGetRegIdForPS4(int index, unsigned int *regId);
int sceRegMgrGetVersion(int *version);
int sceRegMgrGetVersionForPS4(int *version);
int sceRegMgrIsInitOK(void);
int sceRegMgrGetInitError(int *err);
int sceRegMgrSrvGetMachineType(int *type);
int sceRegMgrSrvGetRealMachineType(int *type);
int sceRegMgrSrvGetQAFforReg(void *buf, size_t size);
int sceRegMgrSrvGetRegion(int *region);
int sceRegMgrSrvGetRegionStr(char *buf, size_t size);
int sceRegMgrPrintInfo(void);
int sceRegMgrCheckError(int *err);

static void
hexdump_fp(FILE *fp, const unsigned char *data, size_t len) {
  for(size_t i = 0; i < len; i += 16) {
    fprintf(fp, "  %04zx: ", i);
    for(size_t j = 0; j < 16 && (i+j) < len; j++)
      fprintf(fp, "%02x ", data[i+j]);
    fprintf(fp, "\n");
  }
}

static void
list_dir(FILE *fp, const char *path, int depth) {
  DIR *d = opendir(path);
  if(!d) {
    fprintf(fp, "  %s: cannot open\n", path);
    return;
  }
  struct dirent *ent;
  while((ent = readdir(d))) {
    if(!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
      continue;
    char full[512];
    snprintf(full, sizeof(full), "%s/%s", path, ent->d_name);
    struct stat st;
    if(stat(full, &st)) {
      fprintf(fp, "%*s%s (stat failed)\n", depth*2, "", ent->d_name);
      continue;
    }
    if(S_ISDIR(st.st_mode)) {
      fprintf(fp, "%*s%s/\n", depth*2, "", ent->d_name);
      if(depth < 3)
        list_dir(fp, full, depth+1);
    } else {
      fprintf(fp, "%*s%s  (%ld bytes)\n", depth*2, "", ent->d_name, (long)st.st_size);
    }
  }
  closedir(d);
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

int
main(void) {
  mkdir(OUT_DIR, 0777);
  elevate();
  printf("regdump: elevated\n");

  FILE *fp;
  char path[256];
  snprintf(path, sizeof(path), "%s/regdump.txt", OUT_DIR);
  fp = fopen(path, "w");
  if(!fp) { perror(path); return 1; }

  fprintf(fp, "=== PS5 REGISTRY DUMP ===\n\n");

  /* basic status */
  fprintf(fp, "--- REGMGR STATUS ---\n");
  {
    int val = 0;
    fprintf(fp, "  IsInitOK:  %d\n", sceRegMgrIsInitOK());
    if(!sceRegMgrGetInitError(&val))
      fprintf(fp, "  InitError: 0x%08x\n", val);
    if(!sceRegMgrCheckError(&val))
      fprintf(fp, "  CheckError: 0x%08x\n", val);
    if(!sceRegMgrGetVersion(&val))
      fprintf(fp, "  Version:   %d\n", val);
    if(!sceRegMgrGetVersionForPS4(&val))
      fprintf(fp, "  VersionPS4: %d\n", val);
    if(!sceRegMgrSrvGetMachineType(&val))
      fprintf(fp, "  MachineType: %d (0x%x)\n", val, val);
    if(!sceRegMgrSrvGetRealMachineType(&val))
      fprintf(fp, "  RealMachineType: %d (0x%x)\n", val, val);
    if(!sceRegMgrSrvGetRegion(&val))
      fprintf(fp, "  Region: %d\n", val);
    char regstr[256] = {0};
    if(!sceRegMgrSrvGetRegionStr(regstr, sizeof(regstr)))
      fprintf(fp, "  RegionStr: %s\n", regstr);
  }
  fprintf(fp, "\n");

  /* entry counts */
  fprintf(fp, "--- ENTRY COUNTS ---\n");
  {
    int cnt = 0;
    int err;
    err = sceRegMgrToolGetEntryCnt(&cnt);
    fprintf(fp, "  ToolGetEntryCnt: %s cnt=%d\n", err ? "FAILED" : "OK", cnt);
    printf("regdump: ToolEntryCnt=%d (err=%d)\n", cnt, err);

    err = sceRegMgrDrvGetEntCnt(&cnt);
    fprintf(fp, "  DrvGetEntCnt:  %s cnt=%d\n", err ? "FAILED" : "OK", cnt);
    printf("regdump: DrvEntryCnt=%d (err=%d)\n", cnt, err);

    err = sceRegMgrToolGetUpdateCnt(&cnt);
    fprintf(fp, "  ToolGetUpdateCnt: %s cnt=%d\n", err ? "FAILED" : "OK", cnt);

    err = sceRegMgrDrvGetUpdateCnt(&cnt);
    fprintf(fp, "  DrvGetUpdateCnt: %s cnt=%d\n", err ? "FAILED" : "OK", cnt);
  }
  fprintf(fp, "\n");

  /* enumerate registry files */
  fprintf(fp, "--- REGISTRY FILES (via CntlGetFileName) ---\n");
  {
    int count = 0;
    int err = sceRegMgrCntlGetFilesCount(&count);
    fprintf(fp, "  FilesCount: %s count=%d\n", err ? "FAILED" : "OK", count);
    printf("regdump: FilesCount=%d (err=%d)\n", count, err);

    if(!err && count > 0) {
      for(int i = 0; i < count && i < 100; i++) {
        char fname[512] = {0};
        err = sceRegMgrCntlGetFileName(i, fname, sizeof(fname));
        if(!err)
          fprintf(fp, "  [%d] %s\n", i, fname);
        else
          fprintf(fp, "  [%d] ERR 0x%08x\n", i, err);
      }
    }
  }
  fprintf(fp, "\n");

  /* enumerate events (might contain reg IDs) */
  fprintf(fp, "--- EVENT REG IDs ---\n");
  {
    int cnt = 0;
    int err = sceRegMgrEvtGetCnt(&cnt);
    fprintf(fp, "  EvtGetCnt: %s cnt=%d\n", err ? "FAILED" : "OK", cnt);
    printf("regdump: EvtCnt=%d (err=%d)\n", cnt, err);

    if(!err && cnt > 0) {
      for(int i = 0; i < cnt && i < 500; i++) {
        unsigned int regId = 0;
        err = sceRegMgrEvtGetRegId(i, &regId);
        if(!err)
          fprintf(fp, "  [%d] regId=0x%08x\n", i, regId);
      }
    }

    err = sceRegMgrEvtGetCntForPS4(&cnt);
    fprintf(fp, "  EvtGetCntForPS4: %s cnt=%d\n", err ? "FAILED" : "OK", cnt);
    if(!err && cnt > 0) {
      for(int i = 0; i < cnt && i < 500; i++) {
        unsigned int regId = 0;
        err = sceRegMgrEvtGetRegIdForPS4(i, &regId);
        if(!err)
          fprintf(fp, "  [%d] PS4 regId=0x%08x\n", i, regId);
      }
    }
  }
  fprintf(fp, "\n");

  /* ToolGetInfo — try to dump entry info structs */
  fprintf(fp, "--- TOOL ENTRY INFO (first 50) ---\n");
  {
    int cnt = 0;
    sceRegMgrToolGetEntryCnt(&cnt);
    if(cnt > 50) cnt = 50;
    for(int i = 0; i < cnt; i++) {
      unsigned char info[256] = {0};
      int err = sceRegMgrToolGetInfo(i, info, sizeof(info));
      if(!err) {
        fprintf(fp, "  [%d] ", i);
        /* first 4 bytes might be regId */
        unsigned int regId = *(unsigned int*)info;
        fprintf(fp, "regId?=0x%08x  raw: ", regId);
        for(int j = 0; j < 32; j++)
          fprintf(fp, "%02x", info[j]);
        fprintf(fp, "\n");
      } else {
        fprintf(fp, "  [%d] ERR 0x%08x\n", i, err);
      }
    }
  }
  fprintf(fp, "\n");

  /* QA flags from regmgr */
  fprintf(fp, "--- QAF FOR REG ---\n");
  {
    unsigned char qaf[64] = {0};
    int err = sceRegMgrSrvGetQAFforReg(qaf, sizeof(qaf));
    fprintf(fp, "  SrvGetQAFforReg: %s\n", err ? "FAILED" : "OK");
    if(!err)
      hexdump_fp(fp, qaf, 64);
  }
  fprintf(fp, "\n");

  /* browse filesystem for registry data */
  fprintf(fp, "--- FILESYSTEM: registry-related dirs ---\n");
  const char *dirs[] = {
    "/system_data/priv/mms",
    "/system_data/priv",
    "/system_data/settings",
    "/data/system",
    "/data/system/common",
    "/system/common/lib",
    NULL
  };
  for(int i = 0; dirs[i]; i++) {
    fprintf(fp, "\n  [%s]\n", dirs[i]);
    list_dir(fp, dirs[i], 2);
  }
  fprintf(fp, "\n");

  /* try reading known system keys to confirm what range works */
  fprintf(fp, "--- KNOWN SYSTEM KEYS ---\n");
  struct { unsigned int key; const char *name; } known[] = {
    { 0x02020000, "SYSTEM_language" },
    { 0x02860200, "SYSTEM_SPECIFIC_show_mode" },
    { 0x02410000, "SYSTEM_testbutton_mode" },
    { 0x02800600, "SYSTEM_UPDATE_idu_version" },
    { 0x02010000, "SYSTEM_software_version" },
    { 0x02030000, "SYSTEM_initialize_status" },
    { 0x02040000, "SYSTEM_nickname" },
    { 0x02800000, "SYSTEM_UPDATE_mode" },
    { 0x02880000, "SYSTEM_DOWNLOAD_bgft_mode" },
    { 0x09C00100, "ACCESSIBILITY_DEBUG_tts" },
  };
  int nknown = sizeof(known) / sizeof(known[0]);
  for(int i = 0; i < nknown; i++) {
    int val = -1;
    int err = sceRegMgrGetInt(known[i].key, &val);
    fprintf(fp, "  %-40s [0x%08x] = ", known[i].name, known[i].key);
    if(err)
      fprintf(fp, "ERR 0x%08x\n", err);
    else
      fprintf(fp, "%d (0x%x)\n", val, val);
  }
  fprintf(fp, "\n");

  fclose(fp);
  printf("regdump: wrote %s\n", path);
  printf("regdump: done\n");
  return 0;
}
