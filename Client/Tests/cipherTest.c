#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "../loggerClientFuncs/base64.h"
#define PRIME_LEN 256 //bits
#define GENERATOR 2 // or 5, openssl

unsigned char *lau ="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";
unsigned char *key ="81XKz/lCR0vmsrOENvZZ8RO+OGuOaXmBN6B4Tl8HR1A=";
unsigned char *iv  ="awlp6wLIwsiSNlLGf8KUKg==";
int
main(void)
{

	unsigned char *key = "12345";
	unsigned char *iv = "1111";
	unsigned char *plText = "BUenos dias, matosinos! To tha max power! very nice! indeed! To tha max power!";
	unsigned char encText[256];
	unsigned char decText[256];
	int posEnc = 0;
	int posDec = 0;
	int count  = 0;
	EVP_CIPHER_CTX ctxEnc;
	EVP_CIPHER_CTX ctxDec;

	//cifrar
	//inicializar a cifra
	EVP_CIPHER_CTX_init(&ctxEnc);

	//preparar para cifrar
	EVP_EncryptInit_ex(&ctxEnc, EVP_aes_256_cbc(), NULL, key, iv);

	//cifrar
	EVP_EncryptUpdate(&ctxEnc, encText, &count, plText, strlen(plText)); //terminador
	//EVP_EncryptUpdate(&ctxEnc, encText, &count, plText, strlen(plText) + 1); //terminador

	//atualizar pos
	posEnc += count;

	//finalizar
	EVP_CipherFinal_ex(&ctxEnc, encText + posEnc, &count);
	//limpar
	EVP_CIPHER_CTX_cleanup(&ctxEnc);

	//decifra
	//inicializar decifra
	count = 0;
	EVP_CIPHER_CTX_init(&ctxDec);

	//preparar para cifrar
	EVP_DecryptInit_ex(&ctxDec, EVP_aes_256_cbc(), NULL, key, iv);

	//decifrar
	EVP_DecryptUpdate(&ctxDec, decText, &count, encText, strlen(encText)); // cuidado!

	//atualizar pos
	posDec += count;

	//finalizar
 	EVP_DecryptFinal_ex(&ctxDec, decText + posDec, &count);
 	//limpar
	EVP_CIPHER_CTX_cleanup(&ctxDec);

	//decText[posDec + count - 2] = '\0';
	printf("\n\nResultado: %s\n", decText);

	return 0;
/*
	EVP_CIPHER_CTX ctxDec;
	int count, posDec = 0;
	char lauDec[4000];
	char *keyDec, *ivDec, *mDec; 
	mDec  = b64decode(lau, strlen(lau));
	keyDec= b64decode(key, strlen(key));
	ivDec = b64decode(iv, strlen(iv));

	EVP_CIPHER_CTX_init(&ctxDec);

	//preparar para cifrar
	EVP_DecryptInit_ex(&ctxDec, EVP_aes_256_cbc(), NULL, keyDec, ivDec);

	//decifrar

	EVP_DecryptUpdate(&ctxDec, lauDec, &count, mDec, strlen(lau)); // cuidado!

	//atualizar pos
	posDec += count;

	//finalizar
 	EVP_DecryptFinal_ex(&ctxDec, lauDec + posDec, &count);
 	//limpar
	EVP_CIPHER_CTX_cleanup(&ctxDec);

	//decText[posDec + count - 2] = '\0';
	printf("Mdec sizes%d\n", strlen(mDec));

	printf("Mdec text%s\n", mDec);

	printf("\n\nResultado: %s\n", lauDec);
	return 0;
	*/
}
