#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#define SIZE_p 1024
#define SIZE_number 16

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char const* argv[]) {
    BN_CTX* prime_ctx = BN_CTX_new();
    BIGNUM* p = BN_new(), * g = BN_new(), * a = BN_new(), * b = BN_new(), * A = BN_new(), * B = BN_new(), * sa = BN_new(), * sb = BN_new();
    unsigned char r_alice[SIZE_number], r_bob[SIZE_number];

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    if (RAND_load_file("/dev/random", 64) != 64) {
        handle_errors();
    }

    BN_generate_prime_ex2(p, SIZE_p, 0, NULL, NULL, NULL, prime_ctx);
    BN_set_word(g, 5);

    if (!RAND_bytes(r_bob, SIZE_number)) {
        handle_errors();
    }
    if (!RAND_bytes(r_alice, SIZE_number)) {
        handle_errors();
    }

    BN_bin2bn(r_alice, SIZE_number, a);
    BN_bin2bn(r_bob, SIZE_number, b);

    //first step
    if (!BN_mod_exp(A, g, a, p, prime_ctx)) {
        handle_errors();
    } //Alice
    if (!BN_mod_exp(B, g, b, p, prime_ctx)) {
        handle_errors();
    } //Bob
    //second step
    if (!BN_mod_exp(sa, B, a, p, prime_ctx)) {
        handle_errors();
    } //Alice
    if (!BN_mod_exp(sb, A, b, p, prime_ctx)) {
        handle_errors();
    } //Bob

    if (BN_cmp(sa, sb) == 0) {
        fprintf(stdout, "Success!\nShared secret: ");
        BN_print_fp(stdout, sa);
        printf("\n");
    }
    else {
        fprintf(stdout, "Insuccess! :(\n");
    }

    return 0;
}
