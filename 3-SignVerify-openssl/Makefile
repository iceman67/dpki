OPENSSL_INC=/usr/local/opt/openssl/include
OPENSSL_LIB=/usr/local/opt/openssl/lib

sign_verify: sign.o
	g++ sign.o -L ${OPENSSL_LIB}  -lssl -lcrypto -o sign_verify

sign.o: sign.cpp
	g++ -c  -I ${OPENSSL_INC}  sign.cpp

clean:
	rm *.o sign_verify
