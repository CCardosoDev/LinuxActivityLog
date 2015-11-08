#ifndef __LOGGERFUNC__H
#define __LOGGERFUNC__H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <openssl/dh.h>
#include <openssl/evp.h>

#include "../constants.h"
#include "sessionToken.h"

/**
 * Envia os parametros(g, p, A) para a criacao do tunel seguro Diffie-Hellman  para o servidor. Escreve a resposta do servidor 
 * em messageReceived e retorna o numero de caracteres escritos ou <0 em caso de erro.
 *
 * char *sessionId Identificador de sessao
 * char *seqNumber Numero de sequencia da mensagem
 * DH *dh Abstracao openssl para Diffie-Hellman
 * int socketId fd do socket
 * struct sockaddr_in *dest Destino da mensagem
 * char* messageReceived Buffer para escrita da resposta
 */
int sendDiffieHellmanClientParam(
		char *sessionId, char *seqNumber, DH *dh, int socketId, struct sockaddr_in *dest, char* messageReceived);

/**
 * Utiliza a resposta do servidor para terminar o processo Diffie-Hellman, escreve a chave no buffer masterKey e
 * retorna o numero de caracteres escritos ou <0 em caso de erro.
 * 
 * DH *dh Abstracao openssl para Diffie-Hellman
 * char* messageReceived mensagem recebida do servidor
 * int messageSize tamanho da mensagem
 * unsigned char* masterKey Buffer para escrita da chave
 */
int	finishDiffieHellman(DH *dh, char* messageReceived, int messageSize, unsigned char* masterKey);

/**
 * Verifica a autenticidade do servidor (certificado, assinatura da chave) escreve em sessionToken o token no disco.
 * Retorna <0 em caso de erro
 *
 * unsigned char *masterKey chave do canal
 * char *messageReceived mensagem recebida do servidor
 * int messageSize tamanho da mensagem
 */ 
int authenticateServer(char *seqNumber,unsigned char *masterKey, int masterKeySize,char *messageReceived, int messageSize, char *caPath);

/**
 * Envia as informaos do utilizador de forma a terminar a autenticacao.
 *
 * int socketId fd do socket
 * struct sockaddr_in *dest Destino da mensagem
 */ 
int
sendSelfAuthentication(unsigned char *masterKey, int masterKeySize, char* caPath, int socketId, struct sockaddr_in *dest);

#endif
