#include "../loggerClientFuncs/base64.h"
#include "../loggerClientFuncs/message.h"
#include "../constants.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>


int
main(void)
{

	char message[MESSAGE_MAX_SIZE];
	char singleValue[MESSAGE_MAX_SIZE];
	int size;
	int messageSize;
	printf("Testar a funcão messageDiffieHellmanClientParam: \n");

	messageSize = messagediffieHellmanClientParam("sessionIdPOWER", "123456", "ggg", "ppp", "pubb", message, MESSAGE_MAX_SIZE);
	if(messageSize < 0)
	{
		printf("FAIL!\n");
		return -1;
	}

	printf("Mensagem: %s\n", message);
	printf("Tamanho: %d\n", messageSize);

	printf("\n\nTestar a funcão messageGetSingleValue Atributo: \n");

	size = messageGetSingleValue(message, messageSize, "/diffie-hellman/@session", singleValue, MESSAGE_MAX_SIZE, 0);
	if(size < 0)
	{
		printf("FAIL!\n");
		return -1;
	}
	printf("valor: %s\n", singleValue);
	printf("Tamanho: %d\n", size);

	printf("\n\nTestar a funcão messageGetSingleValue elemento (text()): \n");

	size = messageGetSingleValue(message, messageSize, "/diffie-hellman/A/text()", singleValue, MESSAGE_MAX_SIZE, 0);
	if(size < 0)
	{
		printf("FAIL!\n");
		return -1;
	}
	printf("valor: %s\n", singleValue);
	printf("Tamanho: %d\n", size);
		printf("\n\nTestar a funcão messageGetSingleValue elemento (text()): \n");

	size = messageGetSingleValue(message, messageSize, "/diffie-hellman/A/text()", singleValue, MESSAGE_MAX_SIZE, 1);
	if(size < 0)
	{
		printf("FAIL!\n");
		return -1;
	}
	printf("valor: %s\n", singleValue);
	printf("Tamanho: %d\n", size);
	return 0;
}
