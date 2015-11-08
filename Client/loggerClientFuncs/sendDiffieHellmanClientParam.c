#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <errno.h>
#include "../constants.h"
#include "message.h"
/*
DADOS ENVIADOS EM BASE64
*/
void printSA(struct sockaddr_in sa)
{
	printf("sa = %d, %s, %d\n", sa.sin_family,
		inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
}


int 
sendDiffieHellmanClientParam(char *sessionId, char *seqNumber, DH *dh, int socketId, struct sockaddr_in *dest, char* messageReceived)
{
	unsigned int sourceAddSize;
	char messageSend[MESSAGE_MAX_SIZE];
	struct sockaddr_in sourceAdd; //terminar
	int messageSize;
	char *g, *p, *pub_key;

	g = BN_bn2hex(dh->g);
	p = BN_bn2hex(dh->p);
	pub_key = BN_bn2hex(dh->pub_key);

	//tentar enviar

	messageSize = messagediffieHellmanClientParam(sessionId, seqNumber, g, p, pub_key, messageSend, MESSAGE_MAX_SIZE);
	if (messageSize < 0) return -1;

	messageSize = sendto(socketId, messageSend, messageSize, 0, (struct sockaddr *) dest, sizeof(*dest));
	if (messageSize < 0) return -1;


	messageSize = recvfrom(socketId, messageReceived, MESSAGE_MAX_SIZE, 0, (struct sockaddr*) &sourceAdd, &sourceAddSize);
	if (messageSize < 0) return -1;
		
		//falta verificar pk parou e endereco fonte.

		//if(messagecheckDiffieHellmanResponse(messageReceived, messageSize, sessionId, seqNumber, dh))

	free(g);
	free(p);
	free(pub_key);
	return messageSize; 
}