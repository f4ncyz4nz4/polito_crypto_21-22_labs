#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#define MAXBUF 1024

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}


int main(int argc, char** argv) {


    if (argc != 2) {
        fprintf(stderr, "Invalid parameters. Usage: %s filename\n", argv[0]);
        exit(1);
    }


    FILE* f_in;
    if ((f_in = fopen(argv[1], "r")) == NULL) {
        fprintf(stderr, "Couldn't open the input file, try again\n");
        exit(1);
    }


    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    //EVP_MD_CTX *EVP_MD_CTX_new(void);
    //pedantic mode? Check if md == NULL
    EVP_MD_CTX* md256 = EVP_MD_CTX_new();

    EVP_MD_CTX* md512 = EVP_MD_CTX_new();

    //int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);
    // int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
    // Returns 1 for success and 0 for failure.
    if (!EVP_DigestInit(md256, EVP_sha256()))
        handle_errors();

    if (!EVP_DigestInit(md512, EVP_sha256()))
        handle_errors();

    int n_read;
    unsigned char buffer[MAXBUF];
    while ((n_read = fread(buffer, 1, MAXBUF, f_in)) > 0) {
        // Returns 1 for success and 0 for failure.
        if (!EVP_DigestUpdate(md256, buffer, n_read))
            handle_errors();
        if (!EVP_DigestUpdate(md512, buffer, n_read))
            handle_errors();
    }

    unsigned char sha256[EVP_MD_size(EVP_sha256())];
    unsigned char md_value512[EVP_MD_size(EVP_sha512())];
    int md_len256, md_len512;

    //int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
    if (!EVP_DigestFinal_ex(md256, sha256, &md_len256))
        handle_errors();
    if (!EVP_DigestFinal_ex(md512, md_value512, &md_len512))
        handle_errors();

    // void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
    EVP_MD_CTX_free(md256);
    EVP_MD_CTX_free(md512);

    unsigned char sha512_high[EVP_MD_size(EVP_sha256())];
    unsigned char sha512_low[EVP_MD_size(EVP_sha256())];

    for (int i = 0; i < md_len256; i++) {
        sha512_high[i] = md_value512[i];
        sha512_low[i] = md_value512[i + md_len256];
    }

    //sha256 XOR (sha512_low AND SHA512_high)

    for (int i = 0; i < md_len256; i++) {
        sha256[i] = sha256[i] ^ (sha512_high[i] & sha512_low[i]);
    }

    printf("The digest is: ");
    for (int i = 0; i < md_len256; i++)
        printf("%02x", sha256[i]);
    printf("\n");


    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */
    ERR_free_strings();


    return 0;
}