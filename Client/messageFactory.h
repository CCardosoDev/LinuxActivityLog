int logInMessage(
	char *nBI, 
	char *name, 
	char *hostName, 
	char *message,
	int size);

int challengeResponseMessage(
	char *challResp, 
	char *message,
	int size);

int command(
	char *nBI, 
	char *command, 
	char *message,
	int size);

int tearDown(char *nBI, char *message, int size);

int removeSignature(
	char *signedMessage, 
	char *unsignedMessage, 
	char* signature,
	int size); //cuidado!

int addSignature(
	char *unsignedMessage, 
	char *signature,
	char *signedMessage,
	int size);
