/* Brute-force scan DEVENV registry key range to find all existing keys.
 * Previous scan missed keys due to large step size.
 * We know 0x7802C9C8 (SHELLUI_content_info) exists, so scan 0x7802xxxx with step=1. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ps5/kernel.h>

#define OUT_DIR "/data/testpayload"

int sceRegMgrGetInt(unsigned int regId, int *value);
int sceRegMgrGetStr(unsigned int regId, char *buf, size_t size);
int sceRegMgrGetBin(unsigned int regId, void *buf, size_t size);

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

static int
scan_range_int(FILE *fp, unsigned int start, unsigned int end, unsigned int step,
               const char *label) {
  int found = 0;
  fprintf(fp, "--- %s: 0x%08x - 0x%08x step=%u ---\n", label, start, end, step);
  printf("keyscan: scanning %s (0x%08x-0x%08x step %u)...\n", label, start, end, step);

  for(unsigned int key = start; key <= end; key += step) {
    int val = 0;
    int err = sceRegMgrGetInt(key, &val);
    if(err == 0) {
      fprintf(fp, "  FOUND INT 0x%08x (%u) = %d (0x%x)\n", key, key, val, val);
      printf("  HIT: 0x%08x = %d\n", key, val);
      found++;
    } else if(err != (int)0x800d0203) {
      /* not "entry not found" — different error, key might exist as different type */
      fprintf(fp, "  OTHER 0x%08x (%u) err=0x%08x\n", key, key, err);
      found++;
    }
    /* prevent key from wrapping */
    if(key > 0xFFFFFFF0U - step) break;
  }
  fprintf(fp, "  found: %d\n\n", found);
  printf("keyscan: %s done, found %d\n", label, found);
  return found;
}

static void
try_str_keys(FILE *fp, unsigned int *keys, int nkeys) {
  fprintf(fp, "--- String reads for found keys ---\n");
  for(int i = 0; i < nkeys; i++) {
    char buf[256] = {0};
    int err = sceRegMgrGetStr(keys[i], buf, sizeof(buf));
    if(!err) {
      fprintf(fp, "  STR 0x%08x = \"%s\"\n", keys[i], buf);
    } else if(err != (int)0x800d0203 && err != (int)0x800d0218) {
      fprintf(fp, "  STR 0x%08x err=0x%08x\n", keys[i], err);
    }
  }
  fprintf(fp, "\n");
}

int
main(void) {
  mkdir(OUT_DIR, 0777);
  elevate();
  printf("keyscan: elevated\n");

  FILE *fp;
  char path[256];
  snprintf(path, sizeof(path), "%s/keyscan.txt", OUT_DIR);
  fp = fopen(path, "w");
  if(!fp) { perror(path); return 1; }

  fprintf(fp, "=== DEVENV KEY SCAN ===\n\n");

  /* Phase 1: Fine scan of 0x7802xxxx (TOOL keys live here) — step=1, 65536 keys */
  scan_range_int(fp, 0x78020000, 0x7802FFFF, 1, "DEVENV_TOOL fine");

  /* Phase 2: Broader DEVENV categories — step=0x100 */
  scan_range_int(fp, 0x78000000, 0x7801FFFF, 0x100, "DEVENV 0x7800-0x7801");
  scan_range_int(fp, 0x78030000, 0x780FFFFF, 0x100, "DEVENV 0x7803-0x780F");

  /* Phase 3: Scan some SYSTEM key ranges for reference */
  scan_range_int(fp, 0x02800000, 0x0289FFFF, 0x100, "SYSTEM_SPECIFIC 0x0280-0x0289");

  /* Phase 4: Check wider DEVENV at coarser step */
  scan_range_int(fp, 0x78100000, 0x78FFFFFF, 0x10000, "DEVENV wide 0x7810-0x78FF");

  fclose(fp);
  printf("keyscan: wrote %s\n", path);
  printf("keyscan: done\n");
  return 0;
}
