#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define SIZE 128/8

void err_handler(void){
  ERR_print_errors_fp(stderr);
  abort();
}

int main(){
  unsigned char *key, *iv;
  int i;

  key=(unsigned char*) malloc(SIZE*sizeof(unsigned char));
  iv=(unsigned char*) malloc(SIZE*sizeof(unsigned char));

  if(RAND_load_file("/dev/random", 64) != 64){
    err_handler();
  }

  if(!RAND_bytes(key,SIZE)){
    err_handler();
  }
  if(!RAND_bytes(iv,SIZE)){
    err_handler();
  }

  printf("Random key generated: ");
  for(i=0; i<SIZE ; i++)
    printf("%x ", key[i]);
  printf("\n");

  printf("Random IV generated: ");
  for(i=0; i<SIZE ; i++)
    printf("%x ", iv[i]);
  printf("\n");
  
  free(key);
  free(iv);
  return 0;
}