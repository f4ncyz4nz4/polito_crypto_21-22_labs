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

    unsigned char ipad[EVP_MD_block_size(EVP_sha1())];
    unsigned char opad[EVP_MD_block_size(EVP_sha1())];
    unsigned char key[EVP_MD_block_size(EVP_sha1())];
    unsigned char ikey[EVP_MD_block_size(EVP_sha1())];
    unsigned char okey[EVP_MD_block_size(EVP_sha1())];

    for (int i = 0; i < EVP_MD_block_size(EVP_sha1()); i++) {
        ipad[i] = 54;
        opad[i] = 92;
        key[i] = 190;
    }

    if (argc != 2) {
        fprintf(stderr, "Invalid parameters. Usage: %s filename\n", argv[0]);
        exit(1);
    }

    FILE* f_in;
    if ((f_in = fopen(argv[1], "r")) == NULL) {
        fprintf(stderr, "Couldn't open the input file, try again\n");
        exit(1);
    }

    for (int i = 0; i < EVP_MD_block_size(EVP_sha1()); i++) {
        ikey[i] = key[i] ^ ipad[i];
        okey[i] = key[i] ^ opad[i];
    }

    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    //EVP_MD_CTX *EVP_MD_CTX_new(void);
    //pedantic mode? Check if md == NULL
    EVP_MD_CTX* md = EVP_MD_CTX_new();

    //int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);
    // int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
    // Returns 1 for success and 0 for failure.
    if (!EVP_DigestInit(md, EVP_sha1()))
        handle_errors();

    //first round
    int n_read;
    unsigned char buffer[MAXBUF];

    if (!EVP_DigestUpdate(md, ikey, strlen(ikey)))
        handle_errors();
    while ((n_read = fread(buffer, 1, MAXBUF, f_in)) > 0) {
        // Returns 1 for success and 0 for failure.
        if (!EVP_DigestUpdate(md, buffer, n_read))
            handle_errors();
    }

    unsigned char md_value[EVP_MD_size(EVP_sha1())];
    int md_len;

    //int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
    if (!EVP_DigestFinal_ex(md, md_value, &md_len))
        handle_errors();

    //second round
    if (!EVP_DigestUpdate(md, okey, strlen(ikey)))
        handle_errors();
    if (!EVP_DigestUpdate(md, md_value, md_len))
        handle_errors();

    unsigned char md_value_final[EVP_MD_size(EVP_sha1())];
    int md_len_final;

    if (!EVP_DigestFinal_ex(md, md_value_final, &md_len_final))
        handle_errors();

    // void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
    EVP_MD_CTX_free(md);

    printf("The digest is: ");
    for (int i = 0; i < md_len_final; i++)
        printf("%02x", md_value_final[i]);
    printf("\n");

    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */
    ERR_free_strings();

    return 0;
}