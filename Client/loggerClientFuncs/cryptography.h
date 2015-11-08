#ifndef __crypto__H
#define __crypto__H

#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#include <security/pam_modules.h>
#include <security/pam_client.h>
#include <security/_pam_macros.h>

#include "pteidlib.h"
#include "cryptoki.h"
#include "sessionToken.h"

/**
 * Decifra encMessage com base em iv e key, escreve o resultado em decMessage.
 * Retorna o tamanho da mensagem ou <0 em caso de erro.
 *
 */
int decrypt(unsigned char *iv,unsigned char * key, char *encMessage, int encMessageSize, char* decMessage);

/**
 * Cifra decMessage com base em iv e key, escreve o resultado em encMessage.
 * Retorna o tamanho da mensagem ou <0 em caso de erro.
 *
 */
int encrypt(unsigned char *iv,unsigned char * key, char *decMessage, int decMessageSize, char* encMessage);

/**
 * Cria o certificado x509 a partir de PEM.
 * 
 *
 */
X509* getX509fromPEM(unsigned char *pem, int size);

/**
 * Verifica o certificado.
 *
 *
 */
int verifyCertificate(X509 *certificate, char *caPath);

/**
 * Verifica a assinatura.
 *
 *
 */
int verifySignaturePubKey(X509 *certificate, unsigned char *message, unsigned int messageSize, unsigned char *signature, unsigned long signatureLen);

int 
verifySignaturePubKey2(RSA *pubKey, unsigned char *message, unsigned int messageSize, unsigned char *signature, unsigned long signatureLen);



int CC_findObject ( CK_SESSION_HANDLE sessH, CK_ULONG class, char * label, CK_OBJECT_HANDLE * objH );

/**
 * Assinatura com CC.
 *
 */
int signCitizenCard(/*pam_handle_t *pamh, */unsigned char *message, unsigned int messageSize, unsigned char *signature);

int
decryptServerResponse(SessionToken *token, char *message, int messageSize, char* content, int maxContentSize);

#endif

