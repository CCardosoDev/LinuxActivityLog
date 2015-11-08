#include <fcntl.h>

#include "cryptography.h"
#include "base64.h"
//#include "sessionToken.h"
#include "message.h"



int 
decrypt(unsigned char *iv,unsigned char * key, char *encMessage, int encMessageSize, char* decMessage)
{
	int posDec = 0;
	int count  = 0;
	EVP_CIPHER_CTX ctxDec;
	EVP_CIPHER_CTX_init(&ctxDec);
	EVP_DecryptInit_ex(&ctxDec, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_DecryptUpdate(&ctxDec, (unsigned char *)  decMessage, &count, (unsigned char *) encMessage, encMessageSize); // cuidado!
	posDec += count;
	EVP_DecryptFinal_ex(&ctxDec,(unsigned char *) (decMessage + posDec), &count);
	EVP_CIPHER_CTX_cleanup(&ctxDec);
	//decMessage[posDec + count] = '\0'; //cuidado

	return posDec + count;
}
int 
encrypt(unsigned char *iv,unsigned char * key, char *decMessage, int decMessageSize, char* encMessage)
{
	int posEnc = 0;
	int count  = 0;
	EVP_CIPHER_CTX ctxEnc;
	EVP_CIPHER_CTX_init(&ctxEnc);
	EVP_EncryptInit_ex(&ctxEnc, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_EncryptUpdate(&ctxEnc,(unsigned char *)  encMessage, &count,(unsigned char *)  decMessage, decMessageSize);
	posEnc += count;
	EVP_CipherFinal_ex(&ctxEnc,(unsigned char *) (encMessage + posEnc), &count);
	EVP_CIPHER_CTX_cleanup(&ctxEnc);

	return posEnc + count;
}

X509*
getX509fromPEM(unsigned char *pem, int size)
{

	X509 *certificate;
	BIO *bio;
	bio = BIO_new(BIO_s_mem());
	BIO_write(bio,(const void*)pem,size);
	//printf("Result :%d expected %d\n",BIO_puts(bio,(const void*)pem),size);
	certificate = PEM_read_bio_X509(bio,NULL,0,NULL);
	BIO_free_all(bio);

	return certificate;  
}

int verifyCertificate(X509 *certificate, char *caPath)
{
    OpenSSL_add_all_algorithms();

	X509_STORE *store = NULL;
	X509_STORE_CTX  *vrfy_ctx = NULL;
	int result;
	
	vrfy_ctx = X509_STORE_CTX_new();
	if(vrfy_ctx == NULL)
    {
        EVP_cleanup(); //*COLOCAR NOS OUTROS SITIOS*/
        return 0;
    }
		

	if (!(store=X509_STORE_new()))
	{
		X509_STORE_free(store);
        EVP_cleanup();
		return 0;
	}
	result = X509_STORE_load_locations(store, caPath, NULL);
  	if (result != 1)
  	{
  		X509_STORE_free(store);
        EVP_cleanup();
  		return 0;
  	}

  	X509_STORE_CTX_init(vrfy_ctx, store, certificate, NULL);
  	result = X509_verify_cert(vrfy_ctx);
  	X509_STORE_CTX_free(vrfy_ctx);
  	X509_STORE_free(store);

    EVP_cleanup();
	return result;
}
int 
verifySignaturePubKey(X509 *certificate, unsigned char *message, unsigned int messageSize, unsigned char *signature, unsigned long signatureLen)
{
    SHA_CTX ctx;
    unsigned char digest[20];
    EVP_PKEY *EVPpubkey;
    RSA *pubKey;
    int result;

    //printf("cryptoPower2\n");

	SHA1_Init ( &ctx );
    SHA1_Update ( &ctx, message, messageSize );
    SHA1_Final ( digest, &ctx );

    //printf("verifySignaturePubKey mensagem:\n%s\nde tamanho %d o tamanho da assinatura é:%ld\n\n",message,messageSize,signatureLen);

    EVPpubkey = X509_get_pubkey(certificate);
    if(EVPpubkey == NULL) return 0;

    pubKey = EVP_PKEY_get1_RSA(EVPpubkey);
    if(pubKey == NULL) return 0;

    if (RSA_verify (NID_sha1, digest, sizeof(digest), signature, signatureLen, pubKey ) == 1) 
    	result = 1;
    else
    	result = 0;

    EVP_PKEY_free(EVPpubkey);
    RSA_free(pubKey);

    return result;
}

int 
verifySignaturePubKey2(RSA *pubKey, unsigned char *message, unsigned int messageSize, unsigned char *signature, unsigned long signatureLen)
{
    SHA_CTX ctx;
    unsigned char digest[20];
    int result;


	SHA1_Init ( &ctx );
    SHA1_Update ( &ctx, message, messageSize );
    SHA1_Final ( digest, &ctx );


    if (RSA_verify (NID_sha1, digest, sizeof(digest), signature, signatureLen, pubKey ) == 1) 
    	result = 1;
    else
    	result = 0;

    return result;
}

/*
* Generic function that finds a PKCS#11 object, given its class and
* label, in a crypto token
*/

int 
CC_findObject ( CK_SESSION_HANDLE sessH, CK_ULONG class, char * label, CK_OBJECT_HANDLE * objH )
{
    long ret;
    CK_ATTRIBUTE attrs;
    CK_ULONG objCount;
    unsigned int objValue;

    objValue = class;
    attrs.type = CKA_CLASS;
    attrs.pValue = &objValue;
    attrs.ulValueLen = sizeof(objValue);

    ret = C_FindObjectsInit ( sessH, &attrs, 1 );
    if (ret != CKR_OK) {
	   return -1;
    }

    for (;;) {
    	ret = C_FindObjects ( sessH, objH, 1, &objCount );
    	if (ret != CKR_OK) {
    	    return -1;
    	}
    	if (objCount == 0) return -1;

    	attrs.type = CKA_LABEL;
    	attrs.pValue = 0;
    	attrs.ulValueLen = 1;
    	ret = C_GetAttributeValue ( sessH, *objH, &attrs, 1 );
    	if (ret != CKR_OK) {
    	    return -1;
    	}
    	attrs.pValue = alloca ( attrs.ulValueLen + 1 );
    	((char*)attrs.pValue)[attrs.ulValueLen] = 0;
    	ret = C_GetAttributeValue ( sessH, *objH, &attrs, 1 );
    	if (ret != CKR_OK) {
    	    return -1;
    	}

    	if (strcmp ( attrs.pValue, label ) == 0) {
    	    C_FindObjectsFinal ( sessH );
    	    return CKR_OK;
    	}
    }

    C_FindObjectsFinal ( sessH );
    return CKR_TOKEN_NOT_RECOGNIZED;
}

int
signCitizenCard(/*pam_handle_t *pamh, */unsigned char *message, unsigned int messageSize, unsigned char *signature)
{
    int i;
    CK_RV ret;
    CK_ULONG slots;
    CK_SLOT_ID * slotIds;// slot;
    CK_SLOT_INFO slotInfo;
    CK_TOKEN_INFO tokenInfo;
    CK_SESSION_HANDLE sessH;
    CK_OBJECT_HANDLE objH;
    CK_MECHANISM mechanism;
    CK_ULONG signatureLen;
    CK_BYTE * localSignature;
    //char *PIN = PIN;



    ret = C_Initialize ( 0 );
    if (ret != CKR_OK) {
	   C_Finalize ( 0 );
	   return -1;

    }

    slots = 0;
    ret = C_GetSlotList ( FALSE, 0, &slots );
    if (ret != CKR_OK) {
	   C_Finalize ( 0 );
	   return -1;
    }

    slotIds = alloca ( slots * sizeof(CK_SLOT_ID) );
    ret = C_GetSlotList ( FALSE, slotIds, &slots );
    if (ret != CKR_OK) {
	   C_Finalize ( 0 );
	   return -1;
    }

    for (i = 0; i < slots; i++) {
    	ret = C_GetSlotInfo ( slotIds[i], &slotInfo );
    	if (ret != CKR_OK) {
    	    C_Finalize ( 0 );
    	    return -1;
    	}
    	if (slotInfo.flags & CKF_TOKEN_PRESENT) {
    	    ret = C_GetTokenInfo ( slotIds[i], &tokenInfo );
    	    if (ret != CKR_OK) {
    		  C_Finalize ( 0 );
    		  return -1;
    	    }
    	    if (strncmp ( (const char *)tokenInfo.label, "CARTAO DE CIDADAO", 17 ) == 0) {
    			//slot = slotIds[i];
    		  goto sign;
    	    }
    	}
    }

    return CKR_TOKEN_NOT_PRESENT;
sign:
    /*pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &PIN,
		"Enter PTEID CC Authentication PIN (or return for aborting): ");
    if (strlen ( PIN ) == 0)
	return PAM_AUTH_ERR;
    if (strlen ( PIN ) != 4) {
        goto sign;
    }*/

    /*
    * Encrypt message with CC private key
    */

    ret = C_OpenSession ( 0, CKF_SERIAL_SESSION, 0, 0, &sessH );
    if (ret != CKR_OK) {
    	C_Finalize ( 0 );
    	return -1;
    }

    ret = C_Login ( sessH, CKU_USER, (unsigned char *) PIN, strlen(PIN) );
    if (ret != CKR_OK) {
    	C_Finalize ( 0 );
    	return -1;
    }

    if (CC_findObject ( sessH, CKO_PRIVATE_KEY, "CITIZEN AUTHENTICATION KEY", &objH ) != CKR_OK) {
    	C_Finalize ( 0 );
    	return -1;
    }

    mechanism.mechanism = CKM_SHA1_RSA_PKCS;
    ret = C_SignInit ( sessH, &mechanism, objH );
    if (ret != CKR_OK) {
	   C_Finalize ( 0 );
	   return -1;
    }

    signatureLen = 0;
    ret = C_Sign ( sessH, (CK_BYTE_PTR)message, (CK_ULONG)messageSize, 0, &signatureLen );
    localSignature = alloca ( signatureLen );
    ret = C_Sign ( sessH, (CK_BYTE_PTR)message, (CK_ULONG)messageSize, localSignature, &signatureLen );

    if (ret != CKR_OK) {
	   C_Finalize ( 0 );
	   return -1;
    }

    ret = C_Logout ( sessH );
    if (ret != CKR_OK) {
	   C_Finalize ( 0 );
	   return -1;
    }

    ret = C_CloseSession ( sessH );
    if (ret != CKR_OK) {
        C_Finalize ( 0 );
	   return -1;
    }

    C_Finalize ( 0 );

    memcpy(signature, localSignature, signatureLen);
	return signatureLen;
}

int
decryptServerResponse(SessionToken *token, char *message, int messageSize, char* content, int maxContentSize)
{
    unsigned char iv[IV_MAX_SIZE];
    int ivSize;
    char session[SESSION_MAX_SIZE];
    int sessionSize;
    char encSeqNumber[SEQUENCE_ENC_MAX_SIZE];
    int encSeqNumberSize;
    char decSeqNumber[SEQUENCE_MAX_SIZE];
    int decSeqNumberSize;
    char encMessage[MESSAGE_MAX_SIZE];
    int encMessageSize;
    char decMessage[MESSAGE_MAX_SIZE];
    int decMessageSize = -1;

    sessionSize = messageGetSingleValue(message, messageSize, 
        "/encryptedMessage/@session",session, SESSION_MAX_SIZE, 0);
    if(sessionSize < 0) return -1;

    if(strncmp((char *)session, token->session, sessionSize) != 0)
        return -1;

    ivSize = messageGetSingleValue(message, messageSize, 
        "/encryptedMessage/@iv",(char *) iv, IV_MAX_SIZE, 0);
    if(ivSize < 0) return -1;

    encSeqNumberSize = messageGetSingleValue(message, messageSize, 
        "/encryptedMessage/@seqNumber",encSeqNumber, SEQUENCE_ENC_MAX_SIZE, 1);
    if(encSeqNumberSize < 0) return -1;

    decSeqNumberSize = decrypt(iv, (unsigned char *)token->sessionKey, encSeqNumber, encSeqNumberSize, decSeqNumber);
    if(decSeqNumberSize < 0) return -1;

    if(strncmp(decSeqNumber, token->seqNumber, strlen(token->seqNumber)) != 0)
    {
        return -1;
    }

    encMessageSize = messageGetSingleValue(message, messageSize, 
        "/encryptedMessage/text()",encMessage, MESSAGE_MAX_SIZE, 1);
    if(encMessageSize < 0) return -1;

    decMessageSize = decrypt(iv, (unsigned char *)token->sessionKey, encMessage, encMessageSize, decMessage);
    if(decMessageSize < 0) return -1;

    if (decMessageSize <= maxContentSize)
        memcpy(content, decMessage, decMessageSize);
    else
        return -1;

    return decMessageSize;
}
