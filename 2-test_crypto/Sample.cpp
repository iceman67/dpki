// g++ -g3 -ggdb -O0 -DDEBUG Sample.cpp -o Sample.exe -I/usr/include/cryptopp -lcryptopp

// sample.cpp

#include "integer.h"
using CryptoPP::Integer;

#include "files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "pssr.h"
using CryptoPP::PSSR;

#include "rsa.h"
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSASS;
using CryptoPP::RSA;

#include "filters.h"
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "sha.h"
using CryptoPP::SHA1;

#include <string>
using std::string;

#include <iostream>
using std::cout;
using std::endl;

#include <cryptopp/base64.h>
using CryptoPP::Base64URLEncoder;

#include <cryptopp/queue.h>
using CryptoPP::ByteQueue;

#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;


typedef uint8_t byte;

void SaveKey(const RSA::PublicKey& PublicKey, const string& filename);
void SaveKey(const RSA::PrivateKey& PrivateKey, const string& filename);

/*
void SaveHex(const string& filename, const BufferedTransformation& bt)
{
    HexEncoder encoder;
    bt.CopyTo(encoder);
    encoder.MessageEnd();
    Save(filename, encoder);
}
*/

int main(int argc, char* argv[])
{
    try {

        ////////////////////////////////////////////////
        // Generate keys
        AutoSeededRandomPool rng;

        InvertibleRSAFunction parameters;
        parameters.GenerateRandomWithKeySize(rng, 1536);

        RSA::PrivateKey privateKey(parameters);
        RSA::PublicKey publicKey(parameters); 

        ////////////////////////////////////////////////
        // Handle keys
        const Integer& e = publicKey.GetPublicExponent();
        std:: cout << e << std::endl;
        const Integer& n = publicKey.GetModulus();
        std:: cout << n << std::endl;

	string spki;
	StringSink ss(spki);
	publicKey.Save(ss);

	cout << "publicKey(string) : " << spki << endl;

#if TEST	
        ////////////////////////////////////////////////
        /// Logger generates a private key and a public key
        /// (Logger) transfer a public key(Verify) to a gateway
        /// (Logger) sign a hash using private  key 
        /// (Gateway) verify the hash using the public key
 
        //(Logger) Save to a publicKeyBuffer  (byte*)
	ByteQueue queue;
	publicKey.Save(queue);
        byte publicKeyBuffer[1000];
	size_t size = queue.Get((byte*)&publicKeyBuffer, sizeof(publicKeyBuffer));
        std:: cout << publicKeyBuffer << std::endl;

	/// Logger transfer the buffer (containing public key) to Gateway

	// (Gateway) Load  a key loadkey from publicKeyBuffer 
	RSA::PublicKey loadkey;
	ByteQueue queue2;
	queue2.Put2((byte *)&publicKeyBuffer, size, 0, true);
	
	loadkey.Load(queue2);
        ////////////////////////////////////////////////
#endif 

        ////////////////////////////////////////////////
        // Setup
        string message = "RSA-PSSR Test", signature, recovered;    

        ////////////////////////////////////////////////
        // Sign and Encode
        RSASS<PSSR, SHA1>::Signer signer(privateKey);

        StringSource(message, true, 
            new SignerFilter(rng, signer,
                new StringSink(signature),
                true // putMessage
           ) // SignerFilter
       ); // StringSource

       SaveKey(privateKey, "privkey");

        ////////////////////////////////////////////////
        // Verify and Recover
        RSASS<PSSR, SHA1>::Verifier verifier(publicKey);
#if TEST
        RSASS<PSSR, SHA1>::Verifier verifier(loadkey);
#endif 

        StringSource(signature, true,
            new SignatureVerificationFilter(
                verifier,
                new StringSink(recovered),
                SignatureVerificationFilter::THROW_EXCEPTION |
                SignatureVerificationFilter::PUT_MESSAGE
           ) // SignatureVerificationFilter
       ); // StringSource

        assert(message == recovered);
        cout << "Verified signature on message" << endl;
        cout << "Message: " << "'" << recovered << "'" << endl;

    } // try

    catch(CryptoPP::Exception&e)
    {
        std::cerr << "Error: " << e.what() << endl;
    }

    return 0;
}


void SaveKey(const RSA::PublicKey& PublicKey, const string& filename)
{
    // DER Encode Key - X.509 key format
    PublicKey.Save(
        FileSink(filename.c_str(), true /*binary*/).Ref()
   );
}

void SaveKey(const RSA::PrivateKey& PrivateKey, const string& filename)
{
    // DER Encode Key - PKCS #8 key format
    PrivateKey.Save(
        FileSink(filename.c_str(), true /*binary*/).Ref()
   );
}

void LoadKey(const string& filename, RSA::PublicKey& PublicKey)
{
    // DER Encode Key - X.509 key format
    PublicKey.Load(
        FileSource(filename.c_str(), true, NULL, true /*binary*/).Ref()
   );
}

void LoadKey(const string& filename, RSA::PrivateKey& PrivateKey)
{
    // DER Encode Key - PKCS #8 key format
    PrivateKey.Load(
        FileSource(filename.c_str(), true, NULL, true /*binary*/).Ref()
   );
}

void PrintPrivateKey(const RSA::PrivateKey& key)
{
    cout << "n: " << key.GetModulus() << endl;

    cout << "d: " << key.GetPrivateExponent() << endl;
    cout << "e: " << key.GetPublicExponent() << endl;

    cout << "p: " << key.GetPrime1() << endl;
    cout << "q: " << key.GetPrime2() << endl;
}

void PrintPublicKey(const RSA::PublicKey& key)
{
    cout << "n: " << key.GetModulus() << endl;
    cout << "e: " << key.GetPublicExponent() << endl;
}
