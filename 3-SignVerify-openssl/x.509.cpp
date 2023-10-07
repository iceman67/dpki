// X509.cpp : Defines the entry point for the console application.
//
// openssl pkcs12 -in cert.p12 -nodes \
//    -passin pass:"PASSWORD" | openssl x509 -noout -subject
// subject=C = CA, O = MyCompany, CN = localhost

#include <cstdio>
#include <iostream>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>

/* Generates a 2048-bit RSA key. */
EVP_PKEY *generate_key()
{
    /* Allocate memory for the EVP_PKEY structure. */
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey)
    {
        std::cerr << "Unable to create EVP_PKEY structure." << std::endl;
        return NULL;
    }

    /* Generate the RSA key and assign it to pkey. */
    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    if (!EVP_PKEY_assign_RSA(pkey, rsa))
    {
        std::cerr << "Unable to generate 2048-bit RSA key." << std::endl;
        EVP_PKEY_free(pkey);
        return NULL;
    }

    /* The key has been generated, return it. */
    return pkey;
}

/* Generates a self-signed x509 certificate. */
X509 *generate_x509(EVP_PKEY *pkey)
{
    /* Allocate memory for the X509 structure. */
    X509 *x509 = X509_new();
    if (!x509)
    {
        std::cerr << "Unable to create X509 structure." << std::endl;
        return NULL;
    }

    /* Set the serial number. */
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    /* This certificate is valid from now until exactly one year from now. */
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

    /* Set the public key for our certificate. */
    X509_set_pubkey(x509, pkey);

    /* We want to copy the subject name to the issuer name. */
    X509_NAME *name = X509_get_subject_name(x509);

    /* Set the country code and common name. */
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"CA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"MyCompany", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0);

    /* Now set the issuer name. */
    X509_set_issuer_name(x509, name);

    /* Actually sign the certificate with our key. */
    if (!X509_sign(x509, pkey, EVP_sha1()))
    {
        std::cerr << "Error signing certificate." << std::endl;
        X509_free(x509);
        return NULL;
    }

    return x509;
}

bool write_to_disk(EVP_PKEY *pkey, X509 *x509)
{
    /* Open the PEM file for writing the key to disk. */
    FILE *pkey_file = fopen("key.pem", "wb");
    if (!pkey_file)
    {
        std::cerr << "Unable to open \"key.pem\" for writing." << std::endl;
        return false;
    }

    /* Write the key to disk. */
    bool ret = PEM_write_PrivateKey(pkey_file, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(pkey_file);

    if (!ret)
    {
        std::cerr << "Unable to write private key to disk." << std::endl;
        return false;
    }

    /* Open the PEM file for writing the certificate to disk. */
    FILE *x509_file = fopen("cert.pem", "wb");
    if (!x509_file)
    {
        std::cerr << "Unable to open \"cert.pem\" for writing." << std::endl;
        return false;
    }

    /* Write the certificate to disk. */
    ret = PEM_write_X509(x509_file, x509);
    fclose(x509_file);

    if (!ret)
    {
        std::cerr << "Unable to write certificate to disk." << std::endl;
        return false;
    }

    return true;
}

/* Check the X509 certificate. */
void check_certificate_validaty(X509 *certificate)
{
    /* a newly initialised X509_STORE_CTX structure */
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();

    /* a newly initialised X509_STORE structure */
    X509_STORE *store = X509_STORE_new();

    /* Copy a certificate to X509_STORE structure */
    X509_STORE_add_cert(store, certificate);

    /* Set up a X509_STORE_CTX for verification. */
    X509_STORE_CTX_init(ctx, store, certificate, NULL);

    /* Verify a X.509 certification. */
    if (X509_verify_cert(ctx) == 1)
    {
        printf("Certificate verified ok\n");
    }
    else
    {
        printf("Certificate verified fail\n");
    }
}

bool write_pkcs12()
{

    X509 *cert;
    PKCS12 *p12;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Allocate memory for the EVP_PKEY structure. */
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey)
    {
        std::cerr << "Unable to create EVP_PKEY structure." << std::endl;
        return false;
    }

    /* Open the PEM file for reading the key on disk. */
    FILE *fp = fopen("key.pem", "r");
    if (!fp)
    {
        std::cerr << "Unable to open \"key.pem\" for reading." << std::endl;
        return false;
    }

    /* Read a private key from the PEM file. */
    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if (!pkey)
    {
        std::cerr << "Error loading certificate private key content." << std::endl;
        return false;
    }
    fclose(fp);

    /* Open the PEM file for reading the certificate on disk. */
    fp = fopen("cert.pem", "r");
    if (!fp)
    {
        std::cerr << "Unable to open \"cert.pem\" for reading." << std::endl;
        return false;
    }

    /* Read the X.509 certification from the PEM file. */
    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    rewind(fp);
    fclose(fp);

    /* Allocate memory for the PKCS#12 structure. */
    p12 = PKCS12_create("PASSWORD", "NAME", pkey, cert, NULL, 0, 0, 0, 0, 0);
    if (!p12)
    {
        std::cerr << "Error creating PKCS#12 structure." << std::endl;
        return false;
    }

    /* Open the PEM file for reading the certificate on disk. */
    fp = fopen("cert.p12", "wb");
    if (!fp)
    {
        std::cerr << "Unable to open \"cert.p12\" for reading." << std::endl;
        return false;
    }

    /* Write the PKCS#12 certification to disk */
    i2d_PKCS12_fp(fp, p12);
    PKCS12_free(p12);
    fclose(fp);

    return true;
}

int main()
{
    /* Generate the key. */
    std::cout << "Generating RSA key..." << std::endl;

    EVP_PKEY *pkey = generate_key();
    if (!pkey)
        return 1;

    /* Generate the certificate. */
    std::cout << "Generating x509 certificate..." << std::endl;

    X509 *x509 = generate_x509(pkey);
    if (!x509)
    {
        EVP_PKEY_free(pkey);
        return 1;
    }

    check_certificate_validaty(x509);

    /* Write the private key and certificate out to disk. */
    std::cout << "Writing key and certificate to disk..." << std::endl;

    bool ret = write_to_disk(pkey, x509);
    EVP_PKEY_free(pkey);
    X509_free(x509);

    if (ret)
    {
        std::cout << "Success a writing key and certificate!" << std::endl;
    }
    else
        return 1;

    std::cout << "Writing the pkcs#12 certificate to disk..." << std::endl;
    ret = write_pkcs12();

    if (ret)
    {
        std::cout << "Success the pkcs#12 certificate!" << std::endl;
        return 0;
    }
    else
        return 1;
}