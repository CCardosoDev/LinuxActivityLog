#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
 #include <openssl/dh.h>

#include "../constants.h"
#include "message.h"
/*DADOS EM BASE64*/

//terminar DiffieHellman
int	finishDiffieHellman(DH *dh, char* messageReceived,int  messageSize,unsigned char* masterKey)
{
	char pubKeyString[MASTER_KEY_SIZE];
	int result;
	BIGNUM *pubKey;

	result = messageGetSingleValue(messageReceived, messageSize, 
		"/diffie-hellman/B/text()",pubKeyString, MASTER_KEY_SIZE,1);
	if (result < 0) return -1;

	pubKey = BN_new();
	result = BN_hex2bn(&pubKey, pubKeyString);
	if (result < 0) return -1;
	
	result = DH_compute_key(masterKey, pubKey, dh);
	if (result < 0) return -1;

	BN_free(pubKey);
	
	return result;
}