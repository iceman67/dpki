// openssl genrsa -aes256 -out rootca.key 2048
// rootca.key

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

EVP_PKEY *generate_key()
{
    /* EVP_PKEY structure is for storing an algorithm-independent private key in memory. */
    EVP_PKEY *pkey = EVP_PKEY_new();

    /* Generate a RSA key and assign it to pkey.
     * RSA_generate_key is deprecated.
     */
    BIGNUM *bne = BN_new();
    BN_set_word(bne, RSA_F4);
    RSA *rsa = RSA_new();
    RSA_generate_key_ex(rsa, 2048, bne, NULL);

    EVP_PKEY_assign_RSA(pkey, rsa);

    return pkey;
}

int main()
{
    EVP_PKEY *pkey = generate_key();
    FILE *pkey_file = fopen("rootca.key", "wb");
    PEM_write_PrivateKey(pkey_file, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(pkey_file);

    return 1;
}
