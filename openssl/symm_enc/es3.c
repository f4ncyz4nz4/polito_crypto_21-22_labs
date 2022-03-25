#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>


#define ENCRYPT 1
#define DECRYPT 0
#define MAX_BUFFER 128

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char** argv) {

    //  int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv, int enc);
    //  int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
    //  int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

    if (argc != 2) {
        fprintf(stderr, "Invalid parameters. Usage: %s file_in key iv file_out\n", argv[0]);
        exit(1);
    }

    FILE* f_in, * f_out;
    if ((f_in = fopen(argv[1], "r")) == NULL) {
        fprintf(stderr, "Couldn't open the input file, try again\n");
        abort();
    }
    if ((f_out = fopen("es3.enc", "w")) == NULL) {
        fprintf(stderr, "Couldn't open the output file, try again\n");
        abort();
    }

    unsigned char key[] = "12345678998765432112345678998765123456789987654321123456789987651234567899876543211234567899876512345678998765432112345678998765";

    int length = 0;
    unsigned char ciphertext[MAX_BUFFER];

    int n_read;
    unsigned char buffer[MAX_BUFFER];

    while ((n_read = fread(buffer, 1, MAX_BUFFER, f_in)) > 0) {
        printf("n_Read=%d-", n_read);

        for (int i = 0; i < n_read;i++) {
            ciphertext[i] = buffer[i] ^ key[i];
        }
        length += n_read;

        if (fwrite(ciphertext, 1, n_read, f_out) < n_read) {
            fprintf(stderr, "Error writing the output file\n");
            abort();
        }
    }

    printf("File encrypted!\n");

    return 0;
}