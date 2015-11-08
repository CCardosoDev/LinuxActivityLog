.PHONY : clean

CC=gcc
CFLAGS=-Wall -g -I /usr/local/include/pteid


LIBXML= -I /usr/include/libxml2

#requer libxml2-dev
all: loggerClientFuncs loggerClient loggerClient.so

loggerClient.so:
	ld -o $@ -shared $^ -L /usr/local/lib -lpteidpkcs11 -lssl -lpam -lcrypto -lpteid -lxml2

loggerClient:
	$(CC) $(LIBXML) $(CFLAGS) loggerClient.c -o main.o ./loggerClientFuncs/*.c -lxml2 -L /usr/local/lib -lpteidpkcs11 -lssl -lpam -lcrypto -lpteid

install:
	strip loggerClient.so
	cp loggerClient.so /lib/security

clean:
	rm *.o
	cd loggerClientFuncs;make clean