/* Dump PS5 sysreg files (raw registry database) to /data/testpayload/.
 * Also hex-dumps headers and searches for known patterns. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <ps5/kernel.h>

#define OUT_DIR   "/data/testpayload"
#define REG_DIR   "/system_data/settings"

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
copy_file(const char *src, const char *dst) {
  int fd_in = open(src, O_RDONLY);
  if(fd_in < 0) { printf("  cannot open %s\n", src); return -1; }

  int fd_out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if(fd_out < 0) { close(fd_in); printf("  cannot create %s\n", dst); return -1; }

  char buf[65536];
  ssize_t n;
  size_t total = 0;
  while((n = read(fd_in, buf, sizeof(buf))) > 0) {
    write(fd_out, buf, n);
    total += n;
  }
  close(fd_in);
  close(fd_out);
  printf("  %s -> %s (%zu bytes)\n", src, dst, total);
  return 0;
}

static void
hexdump_region(FILE *fp, const unsigned char *data, size_t len, size_t base) {
  for(size_t i = 0; i < len; i += 16) {
    fprintf(fp, "  %06zx: ", base + i);
    for(size_t j = 0; j < 16 && (i+j) < len; j++)
      fprintf(fp, "%02x ", data[i+j]);
    for(size_t j = (len - i < 16 ? len - i : 16); j < 16; j++)
      fprintf(fp, "   ");
    fprintf(fp, " ");
    for(size_t j = 0; j < 16 && (i+j) < len; j++) {
      unsigned char c = data[i+j];
      fprintf(fp, "%c", (c >= 0x20 && c < 0x7f) ? c : '.');
    }
    fprintf(fp, "\n");
  }
}

static void
analyze_sysreg(const char *filename, FILE *fp) {
  char src[256];
  snprintf(src, sizeof(src), "%s/%s", REG_DIR, filename);

  int fd = open(src, O_RDONLY);
  if(fd < 0) {
    fprintf(fp, "--- %s: cannot open ---\n\n", filename);
    return;
  }

  struct stat st;
  fstat(fd, &st);
  size_t filesz = st.st_size;

  unsigned char *data = malloc(filesz);
  if(!data) { close(fd); return; }
  read(fd, data, filesz);
  close(fd);

  fprintf(fp, "--- %s (%zu bytes) ---\n", filename, filesz);

  /* dump header (first 256 bytes) */
  fprintf(fp, "\nHeader (first 256 bytes):\n");
  hexdump_region(fp, data, filesz < 256 ? filesz : 256, 0);

  /* look for 4-byte aligned values that match known key patterns */
  fprintf(fp, "\nKey-like values (0x02XXXXXX, 0x78XXXXXX, 0x09XXXXXX ranges):\n");
  int found = 0;
  for(size_t i = 0; i + 4 <= filesz; i += 4) {
    unsigned int val = *(unsigned int*)&data[i];
    if((val >= 0x02000000 && val <= 0x02FFFFFF) ||
       (val >= 0x78000000 && val <= 0x78FFFFFF) ||
       (val >= 0x09000000 && val <= 0x09FFFFFF)) {
      fprintf(fp, "  offset 0x%06zx: 0x%08x", i, val);
      /* check if next 4 bytes could be a value */
      if(i + 8 <= filesz) {
        unsigned int next = *(unsigned int*)&data[i+4];
        fprintf(fp, "  next=0x%08x", next);
      }
      /* check for nearby ASCII */
      if(i >= 16) {
        int has_ascii = 0;
        for(int j = -16; j < 0; j++) {
          if(data[i+j] >= 0x20 && data[i+j] < 0x7f) has_ascii++;
        }
        if(has_ascii > 8) {
          fprintf(fp, "  nearby: \"");
          for(int j = -16; j < 0; j++) {
            unsigned char c = data[i+j];
            fprintf(fp, "%c", (c >= 0x20 && c < 0x7f) ? c : '.');
          }
          fprintf(fp, "\"");
        }
      }
      fprintf(fp, "\n");
      found++;
      if(found > 2000) {
        fprintf(fp, "  ... (truncated at 2000 matches)\n");
        break;
      }
    }
  }
  fprintf(fp, "  total matches: %d\n", found);

  /* search for "devenv", "overlay", "devkit", "panel" strings */
  fprintf(fp, "\nString search:\n");
  const char *needles[] = {"devenv", "overlay", "devkit", "panel", "host_overlay",
                           "debug_menu", "show_mode", "sysreg", "DEVENV", NULL};
  for(int n = 0; needles[n]; n++) {
    size_t nlen = strlen(needles[n]);
    for(size_t i = 0; i + nlen <= filesz; i++) {
      if(!memcmp(&data[i], needles[n], nlen)) {
        fprintf(fp, "  \"%s\" found at offset 0x%06zx\n", needles[n], i);
        /* show context */
        size_t ctx_start = (i >= 32) ? i - 32 : 0;
        size_t ctx_len = 80;
        if(ctx_start + ctx_len > filesz) ctx_len = filesz - ctx_start;
        hexdump_region(fp, &data[ctx_start], ctx_len, ctx_start);
      }
    }
  }

  fprintf(fp, "\n");
  free(data);
}

int
main(void) {
  mkdir(OUT_DIR, 0777);
  elevate();
  printf("sysregdump: elevated\n");

  /* copy all sysreg files */
  printf("sysregdump: copying sysreg files...\n");
  const char *files[] = {
    "sysreg.000", "sysreg.001", "sysreg.002", "sysreg.003",
    "sysreg.001.bup", "sysreg.002.bup", NULL
  };
  for(int i = 0; files[i]; i++) {
    char src[256], dst[256];
    snprintf(src, sizeof(src), "%s/%s", REG_DIR, files[i]);
    snprintf(dst, sizeof(dst), "%s/%s", OUT_DIR, files[i]);
    copy_file(src, dst);
  }

  /* analyze each file */
  FILE *fp;
  char path[256];
  snprintf(path, sizeof(path), "%s/sysreg_analysis.txt", OUT_DIR);
  fp = fopen(path, "w");
  if(!fp) { perror(path); return 1; }

  fprintf(fp, "=== SYSREG FILE ANALYSIS ===\n\n");

  for(int i = 0; files[i]; i++)
    analyze_sysreg(files[i], fp);

  fclose(fp);
  printf("sysregdump: wrote %s\n", path);
  printf("sysregdump: done — raw files in %s\n", OUT_DIR);
  return 0;
}
