.PHONY : clean

CC=gcc
CFLAGS=-Wall 

LIBXML= -I /usr/include/libxml2 -I /usr/local/include/pteid

#requer libxml2-dev

all: xmlTester b64Tester signatureTester

signatureTester:
	$(CC) $(LIBXML) $(CFLAGS) signatureTester.c -o signatureTester.o ../loggerClientFuncs/*.c -lxml2 -L /usr/local/lib -lpteidpkcs11 -lssl -lpam -lcrypto -lpteid

xmlTester:
	$(CC) $(LIBXML) $(CFLAGS) xmlTester.c -o xmlTester.o   ../loggerClientFuncs/base64.c ../loggerClientFuncs/message.c -lxml2 -lcrypto

b64Tester: b64Tester.c
	$(CC) $(LIBXML) $(CFLAGS) b64Tester.c -o b64Tester.o   ../loggerClientFuncs/base64.c  -lcrypto

certificates: certificateTester.c
	$(CC) $(LIBXML) $(CFLAGS) certificateTester.c -o certificateTester.o  ../loggerClientFuncs/cryptography.c -lcrypto
clean:
	rm *.o