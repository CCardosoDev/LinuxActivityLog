#include "../loggerClientFuncs/base64.h"
#include "../loggerClientFuncs/message.h"
#include "../constants.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>


int
main(void)
{

	char *message = "Original! Boa sortte!";
	char *b64enc;
	char *b64dec;

	printf("Testar a funcão b64Encode: \n");
	b64enc = b64encode((unsigned char *)message, strlen(message) + 1);
	b64dec = b64decode((unsigned char *)b64enc, strlen(b64enc) + 1);

	printf("Original: %s\n", message); 
	printf("b64: %s\n", b64enc);
	printf("Decode: %s\n", b64dec);

	return 0;
}