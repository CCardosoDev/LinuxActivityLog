#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <openssl/dh.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include "../constants.h"
#include "message.h"
#include "cryptography.h"
#include "sessionToken.h"
#include "base64.h"

int 
authenticateServer(char *seqNumber, unsigned char *masterKey, int masterKeySize, char *messageReceived, int messageSize, char *caPath)
{
	unsigned char iv[IV_MAX_SIZE];
	char encMessage[MESSAGE_MAX_SIZE];
	int encMessageSize;
	char decMessage[MESSAGE_MAX_SIZE];
	int decMessageSize;
	char signature[SIGNATURE_SIZE];
	char tokenString[TOKEN_MAX_SIZE];
	unsigned char certString[CERT_MAX_SIZE];
	int certStringSize;
	int tokenStringSize;
	X509 *cert;
	int result = 0;
	int ivSize;
	char tokenSignature[SIGNATURE_SIZE];
	int tokenSignatureSize;
	char encSeqNumber[SEQUENCE_ENC_MAX_SIZE];
	int encSeqNumberSize;
	char decSeqNumber[SEQUENCE_MAX_SIZE];
	int decSeqNumberSize;


	encMessageSize = messageGetSingleValue(messageReceived, messageSize, 
		"/diffie-hellman/encryptedMessage/text()",encMessage, MESSAGE_MAX_SIZE, 1);
	if(encMessageSize < 0) return -1;
	
	ivSize = messageGetSingleValue(messageReceived, messageSize, 
		"/diffie-hellman/encryptedMessage/@iv",(char *)iv, IV_MAX_SIZE, 0);
	if(ivSize < 0) return -1;

	encSeqNumberSize = messageGetSingleValue(messageReceived, messageSize, 
		"/diffie-hellman/encryptedMessage/@seqNumber",(char *)encSeqNumber, SEQUENCE_ENC_MAX_SIZE, 1);
	if(encSeqNumberSize < 0) return -1;

	decMessageSize = decrypt(iv, masterKey, encMessage, encMessageSize, decMessage);
	if(decMessageSize < 0) return -1;

	//printf("Autentiticacao do servidor\nseqB64:\n%s\ntamanho do seq recebido b64:%d\n", encSeqNumber, encSeqNumberSize);

	decSeqNumberSize = decrypt(iv, masterKey, encSeqNumber, encSeqNumberSize, decSeqNumber);
	if(decSeqNumberSize < 0) return -1;

	if(strncmp(decSeqNumber, seqNumber, strlen(seqNumber)) != 0)
	{
		//printf("Seq recebido %s de tamanho %d\n", decSeqNumber, decSeqNumberSize);
		//printf("Seq esperado %s\n", seqNumber);
		//printf("\nfalha a verificar seqnumbers\n");
		return -1;
	}

	tokenSignatureSize = messageGetSingleValue(decMessage, decMessageSize,
		"/authentication/tokenSignature/text()", (char *) tokenSignature, SIGNATURE_SIZE, 0);
	if(tokenSignatureSize < 0) return -1;

	tokenStringSize = messageGetSingleValue(decMessage, decMessageSize, 
		"/authentication/clientTokenB64/text()",tokenString,TOKEN_MAX_SIZE, 1);//decodeB64
	if(tokenStringSize < 0) return -1;

	certStringSize = messageGetSingleValue(tokenString, tokenStringSize,
		"/clientToken/serverCertificate/text()", (char *) certString, CERT_MAX_SIZE, 0);
	if(certStringSize < 0) return -1;

	cert = getX509fromPEM(certString, strlen((const char *)certString));
	if (cert == NULL) return -1;

	result = verifyCertificate(cert, caPath);
	if(result != 1)
	{
		X509_free(cert);
		return -1;
	}

	result = messageGetSingleValue(decMessage, decMessageSize, 
		"/authentication/secretSignature/text()",signature,SIGNATURE_SIZE, 1);//decodeB64
	if(result < 0)
	{
		X509_free(cert);
		return -1;
	}

	result = verifySignaturePubKey(cert, masterKey, (unsigned int) masterKeySize, 
		(unsigned char *)signature, (unsigned long)result);
	if(!result)
	{
		X509_free(cert);
		return -1;
	}

	result = saveSessionTokenString(tokenString, tokenStringSize, tokenSignature, tokenSignatureSize);
	X509_free(cert);

	return result;
}