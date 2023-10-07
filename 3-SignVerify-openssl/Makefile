OPENSSL_INC=/usr/local/opt/openssl/include
OPENSSL_LIB=/usr/local/opt/openssl/lib



x.509: x.509.cpp
	g++  -o x.509 $(CFLAGS) x.509.cpp -L ${OPENSSL_LIB}  -lssl -lcrypto
	
sign_verify: sign.o
	g++ sign.o -L ${OPENSSL_LIB}  -lssl -lcrypto -o sign_verify

# DPKI, generate root ca
keygen: keygen.c
	gcc keygen.c -o keygen -L ${OPENSSL_LIB}  -lssl -lcrypto

sign.o: sign.cpp
	g++ -c  -I ${OPENSSL_INC}  sign.cpp

clean:
	rm *.o sign_verify
