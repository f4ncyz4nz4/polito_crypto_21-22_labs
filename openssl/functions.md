# OpenSSL

## Random

#### openssl/rand.h

- int RAND_load_file(const char *filename, long max_bytes)
- int RAND_bytes(unsigned char *buf, int num)

## Error and other

#### openssl/err.h

- void ERR_print_errors_fp(FILE *fp)
- ERR_load_crypto_strings()
- OpenSSL_add_all_algorithms()
- CRYPTO_cleanup_all_ex_data()
- ERR_free_strings()
- int CRYPTO_memcmp(const void *a, const void *b, size_t len);

## Digest

#### openssl/evp.h

- EVP_MD_CTX *EVP_MD_CTX_new(void)
- int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl)
- int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt)
- int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s)
- void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
- const EVP_MD *EVP_get_digestbyname(const char *name)
- int EVP_MD_size(const EVP_MD *md)

## HMAC

#### openssl/hmac.h

- HMAC_CTX *HMAC_CTX_new(void)
- int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int key_len, const EVP_MD *md, ENGINE *impl)
- int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, size_t len)
- int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len)
- void HMAC_CTX_free(HMAC_CTX *ctx)

#### openssl/evp.h

- int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey)
- int EVP_DigestSignUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt)
- int EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen)
- EVP_PKEY *EVP_PKEY_new_mac_key(int type, ENGINE *e, const unsigned char *key, int keylen);

## BigNum

#### openssl/bn.h

- BIGNUM *BN_new(void)
- void BN_free(BIGNUM *a)
- BN_CTX *BN_CTX_new(void)
- void BN_CTX_free(BN_CTX *c)
- int BN_bn2bin(const BIGNUM *a, unsigned char *to)
- int BN_print_fp(FILE *fp, const BIGNUM *a)
- int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
- int BN_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx)
- int BN_cmp(BIGNUM *a, BIGNUM *b)
- BIGNUM *BN_generate_prime(BIGNUM *ret, int bits,int safe, BIGNUM *add, BIGNUM *rem, void (*callback)(int, int, void *), void *cb_arg)
- int BN_is_prime(const BIGNUM *p, int nchecks, void (*callback)(int, int, void *), BN_CTX *ctx, void *cb_arg)
- int BN_rand(BIGNUM *rnd, int bits, int top, int bottom)

## Symmetric encryption

#### openssl/evp.h

- EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void)
- int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv, int enc)
- int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv, int enc)
- int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl)
- int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl)
- void EVP_CIPHER_free(EVP_CIPHER *cipher)

## Aymmetric encryption

#### openssl/rsa.h

- int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
- RSA *RSA_new(void)
- void RSA_free(RSA *rsa)
- int RSA_size(const RSA *rsa)
- int RSA_check_key(RSA *rsa)
- int RSA_public_encrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
- int RSA_private_decrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
- int RSA_sign(int type, unsigned char *m, unsigned int m_len, unsigned char *sigret, unsigned int *siglen, RSA *rsa);
- int RSA_verify(int type, unsigned char *m, unsigned int m_len, unsigned char *sigbuf, unsigned int siglen, RSA *rsa)

#### openssl/pem.h

- int PEM_write_RSAPrivateKey(FILE *fp, RSA *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u)
- int PEM_write_PrivateKey(FILE *fp, EVP_PKEY *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u)
- int PEM_write_RSA_PUBKEY(FILE *fp, RSA *x)
- int PEM_write_RSAPublicKey(FILE *fp, RSA *x)
- EVP_PKEY *PEM_read_PrivateKey(FILE *fp, EVP_PKEY **x, pem_password_cb *cb, void *u)
- EVP_PKEY *PEM_read_PUBKEY(FILE *fp, EVP_PKEY **x, pem_password_cb *cb, void *u);
