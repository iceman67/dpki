OPENSSL_INC=/usr/local/opt/openssl/include
OPENSSL_LIB=/usr/local/opt/openssl/lib

keygen : cryptopp-key-gen.cpp
	g++ -I ../cryptopp -o keygen cryptopp-key-gen.cpp -lcryptopp

sample: Sample.cpp
	g++ -I ../cryptopp -o sample Sample.cpp -lcryptopp

test_sv: test_sign_verify.cpp
	g++ -I ../cryptopp -o test_sv test_sign_verify.cpp -lcryptopp

test_rsa_ss: RSA-SS.cpp
	g++ -I ../cryptopp -o test_rsa_ss RSA-SS.cpp -lcryptopp

test_int: test_int.o
	g++ -o test_int test_int.o -lcryptopp

test_int.o: test_int.cpp
	g++ -c test_int.cpp 

sign_verify: sign.o
	g++ sign.o -L ${OPENSSL_LIB}  -lssl -lcrypto -o sign_verify

sign.o: sign.cpp
	g++ -c  -I ${OPENSSL_INC}  sign.cpp


clean:
	rm *.o test_int sign_verify
