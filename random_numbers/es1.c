#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>

#define SIZE 128

int main(){
  unsigned char *buff1, *buff2, *res;
  int i;

  buff1=(char*) malloc(SIZE*sizeof(char));
  buff2=(char*) malloc(SIZE*sizeof(char));
  res=(char*) malloc(SIZE*sizeof(char));

  RAND_bytes(buff1,SIZE);
    //ERR_print_err_fp(stderr);
  RAND_bytes(buff2,SIZE);

  for(i=0; i<SIZE ; i++){
    res[i]=buff1[i]^buff2[i];
  }

  printf("Sequence generated: ");
  for(i=0; i<SIZE ; i++)
    printf("%x ", res[i]);
  printf("\n");
  
  free(buff1);
  free(buff2);
  return 0;
}