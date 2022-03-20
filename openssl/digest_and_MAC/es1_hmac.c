#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define BUFFSIZE 1024

void handle_errors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char const *argv[])
{
    FILE *fd;
    HMAC_CTX *hmac_ctx = HMAC_CTX_new();
    unsigned char key[] = "deepbluedeepblue", buff[BUFFSIZE], hmac_buff[HMAC_size(hmac_ctx)];
    int i, n_buff, n_hmac;

    if (argc != 2)
    {
        fprintf(stdout, "Too few arguments\n");
    }

    if ((fd = fopen(argv[1], "r")) == NULL)
    {
        fprintf(stdout, "Error in opening file\n");
    }

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    if (!HMAC_Init_ex(hmac_ctx, key, strlen(key), EVP_sha512(), NULL))
    {
        handle_errors();
    }

    while ((n_buff = fread(buff, 1, BUFFSIZE, fd)) > 0)
    {
        if (!HMAC_Update(hmac_ctx, buff, n_buff))
        {
            handle_errors();
        }
    }

    if (!HMAC_Final(hmac_ctx, hmac_buff, &n_hmac))
    {
        handle_errors();
    }

    HMAC_CTX_free(hmac_ctx);

    fprintf(stdout, "The HMAC-SHA512 is: ");
    for (i = 0; i < n_hmac; i++)
    {
        fprintf(stdout, "%02x", hmac_buff[i]);
    }
    fprintf(stdout, "\n");

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}