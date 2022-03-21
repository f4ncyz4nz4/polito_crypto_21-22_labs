#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define SIZE 128 / 8

void err_handler(void) {
  ERR_print_errors_fp(stderr);
  abort();
}

int main() {
  unsigned char* buff1, * buff2, * res;
  int i;

  buff1 = (unsigned char*)malloc(SIZE * sizeof(unsigned char));
  buff2 = (unsigned char*)malloc(SIZE * sizeof(unsigned char));
  res = (unsigned char*)malloc(SIZE * sizeof(unsigned char));

  if (RAND_load_file("/dev/random", 64) != 64) {
    err_handler();
  }

  if (!RAND_bytes(buff1, SIZE)) {
    err_handler();
  }
  if (!RAND_bytes(buff2, SIZE)) {
    err_handler();
  }

  for (i = 0; i < SIZE; i++) {
    res[i] = buff1[i] ^ buff2[i];
  }

  printf("Sequence generated: ");
  for (i = 0; i < SIZE; i++)
    printf("%x ", res[i]);
  printf("\n");

  free(buff1);
  free(buff2);
  return 0;
}