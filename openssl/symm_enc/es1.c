#include <stdlib.h>
#include <stdio.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define BUFFSIZE 1024
#define ENCRYPT 1
#define DECRYPT 0

void handle_errors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char const *argv[])
{
    EVP_CIPHER_CTX *ctx;
    FILE *fd;
    unsigned char key[]="1234567887654321", iv[]="1111111111111111", buff[BUFFSIZE], buff_cipher[10000];
    int i, n_buff, cipher_lenght=0, n_cipher_up, final_cipher_lenght, n_key;

    if (argc != 3)
    {
        fprintf(stdout, "Too few arguments\n");
    }

    if ((fd = fopen(argv[1], "r")) == NULL)
    {
        fprintf(stdout, "Error in opening file\n");
    }

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    ctx =EVP_CIPHER_CTX_new();

    if(!EVP_CipherInit(ctx, EVP_get_cipherbyname(argv[2]), key, iv, ENCRYPT)){
        handle_errors();
    }

    while( (n_buff=fread(buff, 1, BUFFSIZE, fd))>0 ){
        if(!EVP_CipherUpdate(ctx, buff_cipher+cipher_lenght, &n_cipher_up, buff, n_buff)){
            handle_errors();
        }
        cipher_lenght+=n_cipher_up;
    }

    if(!EVP_CipherFinal_ex(ctx, buff_cipher+cipher_lenght, &final_cipher_lenght)){
        handle_errors();
    }
    cipher_lenght+=final_cipher_lenght;

    EVP_CIPHER_CTX_free(ctx);

    fprintf(stdout, "Encrypted file: ");
    for (i = 0; i < cipher_lenght; i++)
    {
        fprintf(stdout, "%02x", buff_cipher[i]);
    }
    fprintf(stdout, "\n");

    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();

    return 0;
}