.PHONY : clean

LIBXML= -I /usr/include/libxml2
CC=gcc
CFLAGS=-c -Wall
#requer libxml2-dev
all: authenticateServer.o sendDiffieHellmanClientParam.o sessionToken.o finishDiffieHellman.o sendSelfAuthentication.o 

authenticateServer.o: authenticateServer.c
	$(CC) $(CFLAGS) authenticateServer.c -lcrypto 

sendDiffieHellmanClientParam.o: sendDiffieHellmanClientParam.c message.o
	$(CC) $(CFLAGS) -lcrypto sendDiffieHellmanClientParam.c message.o 

sessionToken.o: sessionToken.c
	$(CC) $(CFLAGS) sessionToken.c -lcrypto 

finishDiffieHellman.o: finishDiffieHellman.c
	$(CC) $(CFLAGS) finishDiffieHellman.c -lcrypto 

sendSelfAuthentication.o: sendSelfAuthentication.c
	$(CC) $(CFLAGS) sendSelfAuthentication.c -lcrypto 

message.o: message.c base64.o
	$(CC) $(CFLAGS) $(LIBXML) message.c base64.o

base64.o: base64.c
	$(CC) $(CFLAGS) base64.c -lcrypto

cryptography.o: cryptography.c
		$(CC) $(CFLAGS) cryptography.c -lcrypto

clean:
		rm *.o