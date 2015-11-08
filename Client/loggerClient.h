#include <openssl/dh.h>
#include <openssl/evp.h>
int sessionStart(char *serverIp, int serverPort);
int sendCommand(char *serverIp, int serverPort, char *command, char *caPath, int verbose);

