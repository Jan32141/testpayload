/* Minimal PS5 payload: shows an on-screen notification and logs to stdout.
 * Build with the ps5-payload-sdk (https://github.com/ps5-payload-dev/sdk). */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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
  printf("Hello from a PS5 payload!\n");
  notify("Hello from a PS5 payload!");

  return 0;
}
