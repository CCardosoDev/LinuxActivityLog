#include <openssl/dh.h>

int 
messagediffieHellmanClientParam(
	char *sessionId, char* seqNumber,
	char* g, char* p, char* pub_key,
	char* messageSend, int messageMaxSize);

/*
	verificação ainda nao esta bem
		falta seq e parametros DH
*/
int 
messagecheckDiffieHellmanResponse(
    char *messageReceived, int messageSize, char *sessionId, char *seqNumber, DH *dh);

/**
	USE ME INSTEAD!
*/
int
messageGetSingleValue(char *messageReceived, int messageSize, char *xPath, char *value, int valueMaxSize, int decodeB64);


int
messageGetTokenString(char *decMessage, int decMessageSize, char *tokenString, int tokenMaxSize);


int
messageCreateEncryptedMessage(
            char *sessionId, 
            unsigned char *iv, int ivSize,
            char *seqNumber,int seqNumberSize,
            unsigned char *encMessage, int encMessageSize,
            char *message, int messageMaxSize);

int
messageCreateCommandMessage(char *date, char *command, char *message, int messageMaxSize);

int
messageCreateTearDownMessage(char *message, int messageMaxSize);

int
messageCreateNewSessionKeyMessage(char *message, int messageMaxSize);

int
messageCreateClientAuthentication(
		unsigned char *masterkeySignature, int signatureSize,
		char *name, int nameSize,
		char *numBI, int numBISize,
		char *userName, int userNameSize,
		char *hostName, int hostNameSize,
		char *message, int messageMaxSize);

int 
messageCheckAck(char *messageReceived, int messageSize);

int
messageRemoveElement(char *original, int originalSize, char *path, char *modified, int maxSize);

