#ifndef __SESSIONTOKEN__H
#define __SESSIONTOKEN__H

#include "../constants.h"

typedef struct 
{
	char session [SESSION_MAX_SIZE];
	char seqNumber [SEQUENCE_MAX_SIZE];
	char sessionKey[SESSION_KEY_MAX_SIZE];
	char serverIP [SERVER_IP_MAX_SIZE];
	char serverPort [SERVER_PORT_MAX_SIZE];
	char iv[IV_MAX_SIZE];
} SessionToken;

/**
 * Recupera o token do disco e guarda-o em sessionToken.
 *
 */
int getSessionToken(SessionToken *sessionToken, char * caPath);

int saveSessionTokenString(char *token, int size, char *signature, int signatureSize);

#endif
