#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>  
#include <openssl/dh.h>
#include <openssl/evp.h>
#include "PTEID_CC.h"
#include "constants.h"
#include "loggerClientFuncs/loggerClientFuncs.h"
#include "loggerClientFuncs/message.h"
#include "loggerClientFuncs/cryptography.h"
#include "loggerClientFuncs/sessionToken.h"

//-- CORREGIIR SAIDA EM CASO DE errors --
//-- Apagar o toke! --
//CAMINHO DA CAcert?
int 
sessionStart(char *serverIp, int serverPort, char* caPath, int verbose)
{
	char messageReceived[MESSAGE_MAX_SIZE];
	char masterKey[MASTER_KEY_SIZE];
	char sessionId[SESSION_MAX_SIZE];
	char seqNumber[SEQUENCE_MAX_SIZE];
	int messageSize, result;
	int socketId;
	struct sockaddr_in dest; //terminar
	struct sockaddr_in source; //terminar
	//struct timeval tv;
	//SessionToken sessionToken;
	//preparar DH
	DH *dh;

	srand( time(NULL) );
	dest.sin_family = AF_INET;
	dest.sin_port = htons(serverPort);
	inet_aton(serverIp, &dest.sin_addr);

	source.sin_family = AF_INET;
	source.sin_port = htons(0);
	source.sin_addr.s_addr = htonl(INADDR_ANY);

	if(verbose) printf("Creating socket...\n");
	socketId = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(socketId < 0) return -1;

	if(verbose) printf("Binding socket...\n");
	result = bind(socketId, (struct sockaddr *)&source, sizeof source);
	if(result < 0) return -1;

	//timeout do socket, para usar dps
	//tv.tv_sec = 20;  /* 30 Secs Timeout */
	//tv.tv_usec = 0;  // Not init'ing this can cause strange errors
	//setsockopt(socketId, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));

	if(verbose) printf("Generating DiffieHellman parameters...\n");
	dh = DH_generate_parameters(PRIME_LEN, GENERATOR, NULL, NULL);
	if(dh == NULL) 
	{
		close(socketId);
		return -1;
	}

	if(verbose) printf("Generating DiffieHellman public key...\n");
	result = DH_generate_key(dh);
	if(result < 0) 	
	{
		DH_free(dh);
		close(socketId);
		return -1;
	}

	//preparar a mensagem a enviar
	sprintf(sessionId, "%d",rand());
	sprintf(seqNumber, "%ld",time(NULL));

	if(verbose) printf("Sending parameters to server...\n");
	messageSize = sendDiffieHellmanClientParam(sessionId, seqNumber, dh, socketId, &dest, messageReceived);
	if(messageSize < 0) 
	{
		DH_free(dh);
		close(socketId);
		return -1;
	}

	//terminar DiffieHellman
	if(verbose) printf("Calculating the masterKey based on server response...\n");
	result = finishDiffieHellman(dh, messageReceived, messageSize,(unsigned char*) masterKey);
	if(result < 0) 
	{
		DH_free(dh);
		close(socketId);
		return -1;
	}
	
	//autenticar o servidor e recuperar o token
	if(verbose) printf("Authenticating Server...\n");
	result = authenticateServer(seqNumber, (unsigned char*) masterKey, DH_size(dh), messageReceived, messageSize, caPath);
	if(result < 0)
	{
		saveSessionTokenString("", 0, "", 0);
		DH_free(dh);
		close(socketId);
		return -1;
	}
	
	//send self data com a nova sessao e nova pass esperar ack
	if(verbose) printf("Sending self data to finish process...\n");
	result = sendSelfAuthentication((unsigned char*) masterKey, DH_size(dh), caPath, socketId, &dest);
	if(result < 0) 
	{
		saveSessionTokenString("", 0, "", 0);
		DH_free(dh);
		close(socketId);
		return -1;
	}

	DH_free(dh);
	close(socketId);

	if(verbose) printf("All done!\n");
	return 0;
}
int requestNewPass(char *serverIp, int serverPort, char *caPath, int verbose)
{
	SessionToken token;
	int messageSize;
	int encMessageSize;
	int encSeqNumberSize;
	char message[MESSAGE_MAX_SIZE];
	char currentTime[30];
	char encSeqNumber[MESSAGE_MAX_SIZE];
	char encMessage[MESSAGE_MAX_SIZE];
	int res;
	int finalSize;
	int socketId;
	struct sockaddr_in dest; //terminar
	struct sockaddr_in source; //terminare
	char messageReceived[MESSAGE_MAX_SIZE];
	int messageReceivedSize;
	char decMessageReceived[MESSAGE_MAX_SIZE];
	int decMessageReceivedSize;
	X509* cert;
	char tokenString[TOKEN_MAX_SIZE];
	unsigned char certString[CERT_MAX_SIZE];
	int certStringSize;
	int tokenStringSize;
	char tokenSignature[SIGNATURE_SIZE];
	int tokenSignatureSize;

	//printf("requestNewPass\n");
	res = getSessionToken(&token, caPath);
	//printf("resultado getToken%d\n", res);
	
	if(res < 0 && res != -3) 
	{
		res = sessionStart(serverIp, serverPort, caPath, 0);
		if(res < 0)	return -1;
		res = getSessionToken(&token, caPath);
		if(res < 0) return -1;	
	}

	//memset(&token, 0, sizeof(&token));


	dest.sin_family = AF_INET;
	dest.sin_port = htons(serverPort);
	inet_aton(serverIp, &dest.sin_addr);

	source.sin_family = AF_INET;
	source.sin_port = htons(0);
	source.sin_addr.s_addr = htonl(INADDR_ANY);

	if(verbose) printf("Creating socket...\n");
	socketId = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(socketId < 0) return -1;

	if(verbose) printf("Binding socket...\n");
	res = bind(socketId, (struct sockaddr *)&source, sizeof source);
	if(res < 0)
	{
		return -1;
		close(socketId);
	} 

	sprintf(currentTime, "%ld", time(NULL));

	messageSize = messageCreateNewSessionKeyMessage(message, MESSAGE_MAX_SIZE);

	encMessageSize = encrypt((unsigned char *) token.iv, (unsigned char *) token.sessionKey, message, messageSize, encMessage);

	encSeqNumberSize = encrypt((unsigned char *) token.iv, (unsigned char *) token.sessionKey, token.seqNumber, strlen(token.seqNumber), encSeqNumber);
	
	finalSize = messageCreateEncryptedMessage(token.session, 
		(unsigned char *)token.iv, sizeof(token.iv), 
		encSeqNumber, encSeqNumberSize, 
		(unsigned char *)encMessage, encMessageSize, 
		message, MESSAGE_MAX_SIZE);



	if (finalSize == -1)
	{
		return -1;
		close(socketId);
	} 

	res = sendto(socketId, message, finalSize, 0, (struct sockaddr *) &dest, sizeof(dest));

	messageReceivedSize = recvfrom(socketId, messageReceived, MESSAGE_MAX_SIZE, 0, NULL, 0);
	if (messageReceivedSize < 0) 	
	{
		close(socketId);
		return -1;
	} 

	decMessageReceivedSize = decryptServerResponse(&token, messageReceived, messageReceivedSize, decMessageReceived, MESSAGE_MAX_SIZE);
	if (decMessageReceivedSize < 0)
	{
		close(socketId);
		return -1;
	} 

	//printf("messageRec:\n %s\n",decMessageReceived );

	tokenSignatureSize = messageGetSingleValue(decMessageReceived, decMessageReceivedSize,
		"/newSessionKey/tokenSignature/text()", (char *) tokenSignature, SIGNATURE_SIZE, 0);
	if(tokenSignatureSize < 0)
	{
		close(socketId);
		return -1;
	} 

	tokenStringSize = messageGetSingleValue(decMessageReceived, decMessageReceivedSize, 
		"/newSessionKey/clientTokenB64/text()",tokenString,TOKEN_MAX_SIZE, 1);//decodeB64
	if(tokenStringSize < 0)
	{
		close(socketId);
		return -1;
	} 

	certStringSize = messageGetSingleValue(tokenString, tokenStringSize,
		"/clientToken/serverCertificate/text()", (char *) certString, CERT_MAX_SIZE, 0);
	if(certStringSize < 0) 	
	{
		close(socketId);
		return -1;
	} 

	cert = getX509fromPEM(certString, strlen((const char *)certString));
	if (cert == NULL) 	
	{
		close(socketId);
		return -1;
	} 

	res = verifyCertificate(cert, caPath);
	if(res != 1)
	{
		X509_free(cert);
		close(socketId);
		return -1;
	}

	res = saveSessionTokenString(tokenString, tokenStringSize, tokenSignature, tokenSignatureSize);
	X509_free(cert);
	close(socketId);
	return res;
}

int tearDown(char *serverIp, int serverPort, char *caPath, int verbose)
{
	SessionToken token;
	int messageSize;
	int encMessageSize;
	int encSeqNumberSize;
	char message[MESSAGE_MAX_SIZE];
	char currentTime[30];
	char encSeqNumber[MESSAGE_MAX_SIZE];
	char encMessage[MESSAGE_MAX_SIZE];
	int res;
	int finalSize;
	int socketId;
	struct sockaddr_in dest; //terminar
	struct sockaddr_in source; //terminare
	char messageReceived[MESSAGE_MAX_SIZE];
	int messageReceivedSize;
	char decMessageReceived[MESSAGE_MAX_SIZE];
	int decMessageReceivedSize;

	//printf("tearDown\n");
	res = getSessionToken(&token, caPath);
	//printf("resultado getToken%d\n", res);
	if (res < 0) 	
	{
		return -1;
	} 

	sprintf(currentTime, "%ld", time(NULL));

	messageSize = messageCreateTearDownMessage(message, MESSAGE_MAX_SIZE);

	encMessageSize = encrypt((unsigned char *) token.iv, (unsigned char *) token.sessionKey, message, messageSize, encMessage);

	encSeqNumberSize = encrypt((unsigned char *) token.iv, (unsigned char *) token.sessionKey, token.seqNumber, strlen(token.seqNumber), encSeqNumber);
	
	finalSize = messageCreateEncryptedMessage(token.session, 
		(unsigned char *)token.iv, sizeof(token.iv), 
		encSeqNumber, encSeqNumberSize, 
		(unsigned char *)encMessage, encMessageSize, 
		message, MESSAGE_MAX_SIZE);

	if (finalSize == -1)
	{
		return -1;
	} 

	dest.sin_family = AF_INET;
	dest.sin_port = htons(serverPort);
	inet_aton(serverIp, &dest.sin_addr);

	source.sin_family = AF_INET;
	source.sin_port = htons(0);
	source.sin_addr.s_addr = htonl(INADDR_ANY);

	if(verbose) printf("Creating socket...\n");
	socketId = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(socketId < 0)
	{
		close(socketId);
		return -1;
	} 

	if(verbose) printf("Binding socket...\n");
	res = bind(socketId, (struct sockaddr *)&source, sizeof source);
	if(res < 0) 
	{
		close(socketId);
		return -1;
	} 

	//printf("\n\nSelf data message: %s\n\n", message);
	res = sendto(socketId, message, finalSize, 0, (struct sockaddr *) &dest, sizeof(dest));

	messageReceivedSize = recvfrom(socketId, messageReceived, MESSAGE_MAX_SIZE, 0, NULL, 0);
	if (messageReceivedSize < 0) 	
	{
		close(socketId);
		return -1;
	} 

	decMessageReceivedSize = decryptServerResponse(&token, messageReceived, messageReceivedSize, decMessageReceived, MESSAGE_MAX_SIZE);
	if (decMessageReceivedSize < 0) 
	{
		close(socketId);
		return -1;
	} 
	//printf("decMessageReceivedSize: %d\n",decMessageReceivedSize);
	//printf("Recebido: %s\n", decMessageReceived);

	res = messageCheckAck(decMessageReceived, decMessageReceivedSize);
	//printf("messageCheckAck: %d\n", res);
	if(res)
	{
		saveSessionTokenString("", 0, "", 0); //destruct token
		close(socketId);
		return 0;
	}

	close(socketId);
	return -1;
}


int sendCommand(char *serverIp, int serverPort, char *command, char *caPath, int verbose)
{
	SessionToken token;
	int messageSize;
	int encMessageSize;
	int encSeqNumberSize;
	char message[MESSAGE_MAX_SIZE];
	char currentTime[30];
	char encSeqNumber[MESSAGE_MAX_SIZE];
	char encMessage[MESSAGE_MAX_SIZE];
	int res;
	int finalSize;
	int socketId;
	struct sockaddr_in dest; //terminar
	struct sockaddr_in source; //terminare
	char messageReceived[MESSAGE_MAX_SIZE];
	int messageReceivedSize;
	char decMessageReceived[MESSAGE_MAX_SIZE];
	int decMessageReceivedSize;

	//printf("sendCommand\n");
	res = getSessionToken(&token, caPath);
	//printf("resultado getToken%d\n", res);
	
	if(res == -3)
		res = requestNewPass(serverIp, serverPort, caPath,0);
	else
		if (res < 0)
			res = sessionStart(serverIp, serverPort, caPath,0);

	if(res < 0) return -1;


	//memset(&token, 0, sizeof(&token));
	res = getSessionToken(&token, caPath);
	if(res < 0) return -1;	

	dest.sin_family = AF_INET;
	dest.sin_port = htons(serverPort);
	inet_aton(serverIp, &dest.sin_addr);

	source.sin_family = AF_INET;
	source.sin_port = htons(0);
	source.sin_addr.s_addr = htonl(INADDR_ANY);

	if(verbose) printf("Creating socket...\n");
	socketId = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(socketId < 0) return -1;

	if(verbose) printf("Binding socket...\n");
	res = bind(socketId, (struct sockaddr *)&source, sizeof source);
	if(res < 0)
	{
		close(socketId);
		return -1;
	} 

	if(verbose) printf("Creating message...\n");
	sprintf(currentTime, "%ld", time(NULL));

	messageSize = messageCreateCommandMessage(currentTime, command, message, MESSAGE_MAX_SIZE);

	encMessageSize = encrypt((unsigned char *) token.iv, (unsigned char *) token.sessionKey, message, messageSize, encMessage);

	encSeqNumberSize = encrypt((unsigned char *) token.iv, (unsigned char *) token.sessionKey, token.seqNumber, strlen(token.seqNumber), encSeqNumber);
	
	finalSize = messageCreateEncryptedMessage(token.session, 
		(unsigned char *)token.iv, sizeof(token.iv), 
		encSeqNumber, encSeqNumberSize, 
		(unsigned char *)encMessage, encMessageSize, 
		message, MESSAGE_MAX_SIZE);

	if (finalSize == -1)
	{
		close(socketId);
		return -1;
	} 
	if(verbose) printf("Sending message...\n");
	res = sendto(socketId, message, finalSize, 0, (struct sockaddr *) &dest, sizeof(dest));

	messageReceivedSize = recvfrom(socketId, messageReceived, MESSAGE_MAX_SIZE, 0, NULL, 0);
	if (messageReceivedSize < 0) 
	{
		close(socketId);
		return -1;
	} 

	decMessageReceivedSize = decryptServerResponse(&token, messageReceived, messageReceivedSize, decMessageReceived, MESSAGE_MAX_SIZE);
	if (decMessageReceivedSize < 0)
	{
		close(socketId);
		return -1;
	} 

	//printf("Ultima mensagem tratada recebida:\n%s\nde tamanho: %d\n",decMessageReceived, decMessageReceivedSize);
	res = messageCheckAck(decMessageReceived, decMessageReceivedSize);
	if(res == 1)
	{
		if(verbose) printf("Acepted by the server!\n");
		close(socketId);
		return 0;
	}
		
	if(verbose) printf("Denied by the server!\n");
	close(socketId);
	return -1;
}


int main()
{
	int result = sessionStart(SERVER_IP, SERVER_PORT, "./caCert.pem", 1);
	
	if(sendCommand(SERVER_IP, SERVER_PORT, "Comando teste" ,"./caCert.pem", 1) != 0)
		printf("Erro no send command\n");
	sendCommand(SERVER_IP, SERVER_PORT, "Boa sorte charlie" ,"./caCert.pem", 1);
	sendCommand(SERVER_IP, SERVER_PORT, "Boa sorte charlie1" ,"./caCert.pem", 1);
	//sleep(60);
	sendCommand(SERVER_IP, SERVER_PORT, "Boa sorte charlie2" ,"./caCert.pem", 1);
	sendCommand(SERVER_IP, SERVER_PORT, "Boa sorte charlie3" ,"./caCert.pem", 1);
	//tearDown(SERVER_IP, SERVER_PORT, "./caCert.pem",1);
	return result;
}

PAM_EXTERN int
pam_sm_open_session ( pam_handle_t *pamh, int flags, int argc,
			const char *argv[] )
{
	if(sessionStart(SERVER_IP, SERVER_PORT, "./caCert.pem", 1) == 0)
		return PAM_SUCCESS;

	return PAM_SESSION_ERR;
}

PAM_EXTERN int
pam_sm_close_session ( pam_handle_t *pamh, int flags, int argc,
			const char *argv[] )
{
	if(tearDown(SERVER_IP, SERVER_PORT, "./caCert.pem",1) == 0)
		return PAM_SUCCESS;

	return PAM_SESSION_ERR;
}