#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#define SIZE 32 / 8

void handle_errors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char const *argv[])
{
    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *bn1 = BN_new(), *bn2 = BN_new(), *bn3 = BN_new(), *mod = BN_new(), *res = BN_new(), *rem = BN_new();
    ;
    unsigned char buf1[SIZE], buf2[SIZE], buf3[SIZE];

    ERR_load_CRYPTO_strings();

    if (RAND_load_file("/dev/random", 64) != 64)
    {
        handle_errors();
    }
    if (!RAND_bytes(buf1, SIZE))
    {
        handle_errors();
    }
    if (!RAND_bytes(buf2, SIZE))
    {
        handle_errors();
    }
    if (!RAND_bytes(buf3, SIZE))
    {
        handle_errors();
    }

    BN_bin2bn(buf1, SIZE, bn1);
    BN_bin2bn(buf2, SIZE, bn2);
    BN_bin2bn(buf3, SIZE, bn3);

    BN_add(res, bn1, bn2);
    fprintf(stdout, "sum = %ld\n", BN_get_word(res));

    BN_sub(res, bn1, bn3);
    fprintf(stdout, "difference = %ld\n", BN_get_word(res));

    BN_set_word(mod, pow(2, 32));

    BN_mod_mul(rem, bn1, bn2, mod, bn_ctx);
    BN_mod_mul(res, rem, bn3, mod, bn_ctx);
    fprintf(stdout, "multiplication = %ld\n", BN_get_word(res));

    if (!BN_div(res, rem, bn3, bn1, bn_ctx))
    {
        handle_errors();
    }
    fprintf(stdout, "division = %ld residual = %ld\n", BN_get_word(res), BN_get_word(rem));

    if (!BN_mod(rem, bn1, bn2, bn_ctx))
    {
        handle_errors();
    }
    fprintf(stdout, "modulus = %ld\n", BN_get_word(rem));

    if (!BN_mod_exp(res, bn1, bn2, bn3, bn_ctx))
    {
        handle_errors();
    }
    fprintf(stdout, "modulus-exp = %ld\n", BN_get_word(res));

    fprintf(stdout, "sum = %ld\n", BN_get_word(bn3));
    fprintf(stdout, "sum = %ld\n", BN_get_word(mod));

    ERR_free_strings();

    return 0;
}
