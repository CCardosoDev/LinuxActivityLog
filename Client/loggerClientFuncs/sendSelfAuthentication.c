#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <openssl/dh.h>
#include <pteid/pteiddefines.h>
#include <pteid/pteidlib.h>
#include "../constants.h"
#include "sessionToken.h"
#include <pwd.h>
#include "cryptography.h"
#include "message.h"
#include "base64.h"

typedef struct
{
	char name[PTEID_MAX_NAME_LEN + PTEID_MAX_NAME_LEN];
	char numBI[PTEID_MAX_NUMBI_LEN];
	char userName[MAX_USER_NAME_SIZE];
	char hostName[MAX_HOSTNAME_SIZE];
} UserData;



static int 
getUserData(UserData *data)
{
	int result;
    PTEID_ID pteid_id;
    struct passwd *p;
	p = getpwuid(getuid()); 
	if(p == NULL) return -1;

	result = PTEID_Init ( 0 );
	if (result != PTEID_OK) {
		return -1;
	}
	
	result = PTEID_SetSODChecking(0);
	if (result != PTEID_OK) {
		return -1;
	}

	result = PTEID_GetID ( &pteid_id );
	if (result != PTEID_OK) {
		return -1;
	}
	
	result = PTEID_SetSODChecking(0);
	if (result != PTEID_OK) {
		return -1;
	}

	result = PTEID_Exit ( 0 );
	if (result != PTEID_OK) {
		return -1;
	}

	strncpy(data->name, pteid_id.firstname, PTEID_MAX_NAME_LEN);
	strcat(data->name," ");
	strncat(data->name, pteid_id.name, PTEID_MAX_NAME_LEN);
	data->name[PTEID_MAX_NAME_LEN -1] = '\0';
	strncpy(data->numBI, pteid_id.numBI, PTEID_MAX_NUMBI_LEN);
	data->numBI[PTEID_MAX_NUMBI_LEN -1] = '\0';
	strncpy(data->userName, p->pw_name, MAX_USER_NAME_SIZE);
	data->userName[MAX_USER_NAME_SIZE -1] = '\0';
	result = gethostname(data->hostName, MAX_HOSTNAME_SIZE);
	if(result != 0) return -1;

	return 0;
}


int
sendSelfAuthentication(unsigned char *masterKey, int masterKeySize, char* caPath  ,int socketId, struct sockaddr_in *dest)
{
	UserData data;
	SessionToken token;
	char masterkeySignature[SIGNATURE_SIZE];
	int masterkeySignatureSize;
	int result = 1;
	char plainMessage[MESSAGE_MAX_SIZE];
	char encMessage[MESSAGE_MAX_SIZE];
	int encMessageSize;
	char finalMessage[MESSAGE_MAX_SIZE];
	char messageReceived[MESSAGE_MAX_SIZE];
	unsigned int sourceAddSize;
	int finalSize;
	struct sockaddr_in sourceAdd; //terminar
	char encSeqNumber[SEQUENCE_ENC_MAX_SIZE];
	int encSeqNumberSize;
	char decMessageReceived[MESSAGE_MAX_SIZE];
	int decMessageReceivedSize;

	//printf("	sendSelfAuthentication inicio\n");

	//printf("	gettin card data\n");

/*
	printf("\nSelf session: %s\n", token.session);
	printf("Self seqNumber: %s\n", token.seqNumber);
	printf("Self sessionKey: %s\n", token.sessionKey);
	printf("Self ip: %s\n", token.serverIP);
	printf("Self port: %s\n", token.serverPort);
*/
	result = getUserData(&data);
	if (result < 0) return -1;
	//printf("	done gettin card data\n");
/*
	printf("\nSelf data name: %s\n", data.name);
	printf("Self data numBI: %s\n", data.numBI);
	printf("Self data userName: %s\n", data.userName);
	printf("Self data hostName: %s\n", data.hostName);
*/
	masterkeySignatureSize = signCitizenCard(masterKey, masterKeySize,( unsigned char *) masterkeySignature);
	if (masterkeySignatureSize < 0) return -1;
	/*strcpy(masterkeySignature, "boasorte");
	masterkeySignatureSize = strlen(masterkeySignature);*/

	//printf("	Assinado!\n");

	result = getSessionToken(&token, caPath);
	if (result < 0) return -1;
	
	result = messageCreateClientAuthentication(
		(unsigned char *)masterkeySignature, masterkeySignatureSize,
		data.name, strlen(data.name) + 1,
		data.numBI, strlen(data.numBI) + 1,
		data.userName, strlen(data.userName) + 1,
		data.hostName, strlen(data.hostName) + 1,
		plainMessage, MESSAGE_MAX_SIZE);
	if (result < 0) return -1;


	encMessageSize = encrypt((unsigned char *) token.iv, (unsigned char *) token.sessionKey, plainMessage, result, encMessage);
	if (encMessageSize < 0) return -1;

	encSeqNumberSize = encrypt((unsigned char *) token.iv, (unsigned char *) token.sessionKey, token.seqNumber, strlen(token.seqNumber), encSeqNumber);
	if (encSeqNumberSize < 0) return -1;

	finalSize = messageCreateEncryptedMessage(
		token.session,
		(unsigned char *)token.iv,sizeof token.iv, 
		encSeqNumber, encSeqNumberSize,
		(unsigned char *) encMessage, encMessageSize,
		finalMessage, MESSAGE_MAX_SIZE);
	if (finalSize < 0) return -1;


	//printf("\n\nSelf data message: %s\n\n", finalMessage);
	result = sendto(socketId, finalMessage, finalSize, 0, (struct sockaddr *) dest, sizeof(*dest));
	if (result < 0) return -1;
	//printf("Waiting...\n");
	result = recvfrom(socketId, messageReceived, MESSAGE_MAX_SIZE, 0, (struct sockaddr*) &sourceAdd, &sourceAddSize);
	if (result < 0) return -1;

	//printf("Ultima mensagem recebida:\n%s\nde tamanho: %d\n",messageReceived, result);

	
	decMessageReceivedSize = decryptServerResponse(&token, messageReceived, result, decMessageReceived, MESSAGE_MAX_SIZE);
	if (decMessageReceivedSize < 0) return -1;
	//printf("Ultima mensagem tratada recebida:\n%s\nde tamanho: %d\n",decMessageReceived, decMessageReceivedSize);
	
	if(messageCheckAck(decMessageReceived, decMessageReceivedSize) == 1)
		return 0;

	return -1;
}