#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <pwd.h>
#include "../constants.h"
#include "sessionToken.h"
#include "cryptography.h"
#include "message.h"
#include "base64.h"
#include <errno.h>
#include <fcntl.h>

static int 
readTokenFile(char *tokenString, char* signature, int *signatureSize)
{
	FILE* file;
	char path[512];
	char signatureB64[SIGNATURE_SIZE];
	int signatureB64Size;
	char *tempSig;
	struct passwd *p;

	int temp;
	int result;
	temp = umask(0);
	int dirStatus = mkdir("/tmp/cc", 0777);
	umask(temp);

	if(!(dirStatus ==  0 || (dirStatus == -1 && errno == EEXIST)))
		return -1; //no dir

	p = getpwuid(getuid());  
	if(p == NULL) return -1;

	strcpy(path,"/tmp/cc/");
	strcat(path, p->pw_name);
	
	//printf("lendo o otken de :%s\n", path);
	file = fopen(path, "r");
	if (file == NULL) {
		return -2;
	}

	fscanf(file, "%s", signatureB64);
	signatureB64Size = strlen(signatureB64);
	//printf("assinatura: %s\ntamanho assinatura: %d\n", signatureB64,signatureB64Size);
	tempSig = b64decode((unsigned char *) signatureB64, signatureB64Size, signatureSize);
	memcpy(signature, tempSig, *signatureSize);

	fscanf(file, "%*c");
	result = fread(tokenString, TOKEN_MAX_SIZE, sizeof(char), file);

	fclose(file);
	free(tempSig);
	return result;
}
static int
verifyIntegrity(char *tokenString, int tokenStringSize, char *tokenSignature, int tokenSignatureSize,char * caPath)
{
	unsigned char certString [CERT_MAX_SIZE];
	int certStringSize;
	int result;
	X509 *cert;

	certStringSize = messageGetSingleValue(tokenString, tokenStringSize,
		"/clientToken/serverCertificate/text()", (char *) certString, CERT_MAX_SIZE, 0);
	//printf("certStringSize %d\n", certStringSize);
	if(certStringSize < 0) return -1;

	cert = getX509fromPEM(certString, strlen((const char *)certString));
	if (cert == NULL) return -1;
	//printf("cert OK\n");
	result = verifyCertificate(cert, caPath);
	if(result != 1)
	{
		X509_free(cert);
		return -1;
	}
//printf("cryptoPower1\n");
	result = verifySignaturePubKey(cert, (unsigned char *)tokenString, (unsigned int) tokenStringSize, 
		(unsigned char *)tokenSignature, (unsigned long)tokenSignatureSize);
	//printf("cryptoPower3 res: %d\n", result);
	if(result != 1)
	{
		X509_free(cert);
		return -1;
	}
	//printf("Assinatura Ok\n");
	X509_free(cert);
	return 0;
}
static int
verifyDate(char *tokenString, int tokenStringSize)
{
	unsigned char date [SEQUENCE_MAX_SIZE];
	int dateSize;
	long expirationDate;
	dateSize = messageGetSingleValue(tokenString, tokenStringSize,
		"/clientToken/expirationDate/text()", (char *) date, SEQUENCE_MAX_SIZE, 0);
	if(dateSize < 0) return -1;

	sscanf((char *)date, "%ld", &expirationDate);

	//printf("token epoch: %ld\n", expirationDate);

	if(expirationDate - time(NULL) < 0)
	{
		return -3;
	}
		
	return 0;
}
int
getSessionToken(SessionToken *sessionToken, char *caPath)
{
	int fd;
	int result;
	char tokenString[TOKEN_MAX_SIZE];
	char tokenSignature[SIGNATURE_SIZE];
	int tokenSignatureSize;
	int verifyDateResult;

	memset(tokenString, 0, TOKEN_MAX_SIZE);
	memset(tokenSignature, 0, SIGNATURE_SIZE);

	result = readTokenFile(tokenString, tokenSignature, &tokenSignatureSize);
	if(result < 0) return -1;
	//printf("token lido!\n%s\n",tokenString);
	result = verifyIntegrity(tokenString, strlen(tokenString), tokenSignature, strlen(tokenSignature),caPath);
	if(result < 0) return -1;
	//printf("token integro!\n");
	verifyDateResult = verifyDate(tokenString, strlen(tokenString));
	if(verifyDateResult < 0 && verifyDateResult != -3) return verifyDateResult;
	//printf("token data!\n");
	result = messageGetSingleValue(tokenString, strlen(tokenString), 
		"/clientToken/@session", sessionToken->session, SESSION_MAX_SIZE, 0);
	if(result < 0) return -1;

	/*result = messageGetSingleValue(tokenString, strlen(tokenString), 
		"/clientToken/sessionKey/text()", sessionToken->sessionId, SESSION_MAX_SIZE, 0);
	if(result < 0) return -1;*/

	result = messageGetSingleValue(tokenString, strlen(tokenString), 
		"/clientToken/sessionKey/text()", sessionToken->sessionKey, SESSION_KEY_MAX_SIZE, 0);
	if(result < 0) return -1;

	result = messageGetSingleValue(tokenString, strlen(tokenString), 
		"/clientToken/serverIP/text()", sessionToken->serverIP, SERVER_IP_MAX_SIZE, 0);
	if(result < 0) return -1;

	result = messageGetSingleValue(tokenString, strlen(tokenString), 
		"/clientToken/serverPort/text()", sessionToken->serverPort, SERVER_PORT_MAX_SIZE, 0);
	if(result < 0) return -1;

	fd = open ( "/dev/urandom", O_RDONLY );
	if(fd < 0) return -1;
    read ( fd, sessionToken->iv, sizeof(sessionToken->iv));
    close ( fd );

    sprintf(sessionToken->seqNumber, "%ld",time(NULL));
	//strcpy(sessionToken->seqNumber, "1234");

	return verifyDateResult;
}

/**
	http://crypto.junod.info/2012/12/13/hash-dos-and-btrfs
*/
int saveSessionTokenString(char *token, int size, char *signature, int signatureSize)
{
	FILE* file;
	char path[512];
	struct passwd *p;
	int result;
	int temp;

	//printf("Gravando el token\n");

	temp = umask(0);
	int dirStatus = mkdir("/tmp/cc", 0777);
	umask(temp);

	if(!(dirStatus == 0 || (dirStatus == -1 && errno == EEXIST)))
		return -1; //no dir

	p = getpwuid(getuid());  
	if(p == NULL) return -1;

	strcpy(path,"/tmp/cc/");
	strcat(path, p->pw_name);


	file = fopen(path, "w");
	if (file == NULL) {
		return -1;
	}

	result = fchmod( fileno(file), S_IRUSR | S_IWUSR); //RW by user!
	if(result != 0) 
	{
		fclose(file);
		return -1;
	}

	fprintf(file, "%s\n", signature);	
	fprintf(file, "%s", token);	

	if (fclose(file) != 0)
		return  -1;

	return 0;
}