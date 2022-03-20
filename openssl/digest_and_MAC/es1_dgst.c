#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define BUFFSIZE 1024

void handle_errors(){
  ERR_print_errors_fp(stderr);
  abort();
}

int main(int argc, char const **argv) {
  EVP_MD_CTX *md;
  FILE* fd;
  unsigned int i, r_byte, md_byte;
  unsigned char buff[BUFFSIZE], md_buff[EVP_MD_size(EVP_sha1())];

  if(argc!=2){
    fprintf(stderr, "Too few arguments");
    abort();
  }

  if((fd=fopen(argv[1], "r"))==NULL){
    fprintf(stderr, "Error in opening file");
    abort();
  }

  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  md=EVP_MD_CTX_new();
  if(md==NULL){
    fprintf(stderr, "Error allocate context");
    abort();
  }

  if(!EVP_DigestInit(md, EVP_sha1())){
    handle_errors();
  }

  while((r_byte=fread(buff, 1, BUFFSIZE, fd))>0){
    if(!EVP_DigestUpdate(md, buff, r_byte)){
      handle_errors();
    }
  }

  if(!EVP_DigestFinal(md, md_buff, &md_byte)){
    handle_errors();
  }

  EVP_MD_CTX_free(md);

  fprintf(stdout, "The hashed value is: ");
  for (i = 0; i < md_byte; i++) {
    fprintf(stdout, "%02x", md_buff[i]);
  }
  fprintf(stdout, "\n");

  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();

  return 0;
}
