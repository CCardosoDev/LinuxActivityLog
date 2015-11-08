#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/dh.h>
#include "base64.h"

#include "message.h"

int messagediffieHellmanClientParam(
	char *sessionId, char* seqNumber,
	char* g, char* p, char* pub_key,
	char* message, int messageMaxSize)
{
    int result;
    xmlChar *s;
	xmlDocPtr doc = NULL;       /* document pointer */
    xmlNodePtr root_node = NULL;/* node pointers */

	int messageSize;
	char *gBase64, *pBase64, *pub_keyBase64;

	gBase64 = b64encode((unsigned char*) g, strlen(g) + 1);
	pBase64 = b64encode((unsigned char*) p, strlen(p) + 1);
	pub_keyBase64 = b64encode((unsigned char*) pub_key, strlen(pub_key) + 1);


    LIBXML_TEST_VERSION;

	doc = xmlNewDoc(BAD_CAST "1.0");
    root_node = xmlNewNode(NULL, BAD_CAST "diffie-hellman");
    xmlDocSetRootElement(doc, root_node);

    xmlSetProp(root_node, BAD_CAST "seqNumber",BAD_CAST seqNumber);
    xmlSetProp(root_node, BAD_CAST "session", BAD_CAST sessionId);
    xmlSetProp(root_node, BAD_CAST "type", BAD_CAST "clientParam");

    xmlNewChild(root_node, NULL, BAD_CAST "g",BAD_CAST gBase64);
    xmlNewChild(root_node, NULL, BAD_CAST "p",BAD_CAST pBase64);
    xmlNewChild(root_node, NULL, BAD_CAST "A",BAD_CAST pub_keyBase64);

    xmlDocDumpMemory(doc, &s, &messageSize);

    if( messageSize + 1 <= messageMaxSize)
    {
        strcpy((char *) message, (char *) s);
        result = messageSize + 1;
    }       
    else
        result = -1;

    free(gBase64);
    free(pBase64);
    free(pub_keyBase64);
    xmlFree(s);

    xmlFreeDoc(doc);
    xmlCleanupParser();

    return result;
}

int
messageCreateCommandMessage(char *date, char *command, char *message, int messageMaxSize)
{
    xmlChar *s;
    xmlDocPtr doc = NULL;       /* document pointer */
    xmlNodePtr root_node = NULL;/* node pointers */
    int result;
    int messageSize;

    LIBXML_TEST_VERSION;

    doc = xmlNewDoc(BAD_CAST "1.0");
    root_node = xmlNewNode(NULL, BAD_CAST "command"); //watch out
    xmlDocSetRootElement(doc, root_node);
    xmlNodeSetContent(root_node, BAD_CAST command);

    xmlSetProp(root_node, BAD_CAST "date",BAD_CAST date);

    xmlDocDumpMemory(doc, &s, &messageSize);
    if( messageSize + 1 <= messageMaxSize)
    {
        strcpy((char *) message, (char *) s);
        result = messageSize + 1;
    }       
    else
        result = -1;

    xmlFree(s);

    xmlFreeDoc(doc);
    xmlCleanupParser();

    return result;
}

int
messageCreateTearDownMessage(char *message, int messageMaxSize)
{
    xmlChar *s;
    xmlDocPtr doc = NULL;       /* document pointer */
    xmlNodePtr root_node = NULL;/* node pointers */
    int result;
    int messageSize;

    LIBXML_TEST_VERSION;

    doc = xmlNewDoc(BAD_CAST "1.0");
    root_node = xmlNewNode(NULL, BAD_CAST "tearDown"); //watch out
    xmlDocSetRootElement(doc, root_node);

    xmlDocDumpMemory(doc, &s, &messageSize);
    if( messageSize + 1 <= messageMaxSize)
    {
        strcpy((char *) message, (char *) s);
        result = messageSize + 1;
    }       
    else
        result = -1;

    xmlFree(s);

    xmlFreeDoc(doc);
    xmlCleanupParser();

    return result;
}

int
messageCreateNewSessionKeyMessage(char *message, int messageMaxSize)
{
    xmlChar *s;
    xmlDocPtr doc = NULL;       /* document pointer */
    xmlNodePtr root_node = NULL;/* node pointers */
    int result;
    int messageSize;

    LIBXML_TEST_VERSION;

    doc = xmlNewDoc(BAD_CAST "1.0");
    root_node = xmlNewNode(NULL, BAD_CAST "newSessionKey"); //watch out
    xmlDocSetRootElement(doc, root_node);
    //xmlNodeSetContent(root_node, BAD_CAST command);

    xmlSetProp(root_node, BAD_CAST "type",BAD_CAST "request");

    xmlDocDumpMemory(doc, &s, &messageSize);
    if( messageSize + 1 <= messageMaxSize)
    {
        strcpy((char *) message, (char *) s);
        result = messageSize + 1;
    }       
    else
        result = -1;

    xmlFree(s);

    xmlFreeDoc(doc);
    xmlCleanupParser();

    return result;   
}

int
messageCreateEncryptedMessage(
            char *sessionId, 
            unsigned char *iv, int ivSize,
            char *seqNumber,int seqNumberSize,
            unsigned char *encMessage, int encMessageSize,
            char *message, int messageMaxSize)
{
    xmlChar *s;
    xmlDocPtr doc = NULL;       /* document pointer */
    xmlNodePtr root_node = NULL;/* node pointers */
    int result;
    int messageSize;
    char *ivBase64, *encBase64, *seqBase64;

    seqBase64 = b64encode((unsigned char *)seqNumber, seqNumberSize);
    ivBase64 = b64encode(iv, ivSize);
    encBase64 = b64encode(encMessage, encMessageSize);

    LIBXML_TEST_VERSION;

    doc = xmlNewDoc(BAD_CAST "1.0");
    root_node = xmlNewNode(NULL, BAD_CAST "encryptedMessage");
    xmlDocSetRootElement(doc, root_node);

    xmlNodeSetContent(root_node, BAD_CAST encBase64);

    xmlSetProp(root_node, BAD_CAST "seqNumber",BAD_CAST seqBase64);
    xmlSetProp(root_node, BAD_CAST "session", BAD_CAST sessionId);
    xmlSetProp(root_node, BAD_CAST "iv", BAD_CAST ivBase64);

    xmlDocDumpMemory(doc, &s, &messageSize);

    if( messageSize + 1 <= messageMaxSize)
    {
        strcpy((char *) message, (char *) s);
        result = messageSize + 1;
    }       
    else
        result = -1;

    free(seqBase64);
    free(ivBase64);
    free(encBase64);
    xmlFree(s);

    xmlFreeDoc(doc);
    xmlCleanupParser();

    return result;
}


int
messageCreateClientAuthentication(
        unsigned char *masterkeySignature, int signatureSize,
        char *name, int nameSize,
        char *numBI, int numBISize,
        char *userName, int userNameSize,
        char *hostName, int hostNameSize,
        char *message, int messageMaxSize)
{
    xmlChar *s;
    xmlDocPtr doc = NULL;       /* document pointer */
    xmlNodePtr root_node = NULL;/* node pointers */
    int result;
    int messageSize;
    char *sigBase64;

    sigBase64 = b64encode(masterkeySignature, signatureSize);

    LIBXML_TEST_VERSION;

    doc = xmlNewDoc(BAD_CAST "1.0");
    root_node = xmlNewNode(NULL, BAD_CAST "authentication");
    xmlDocSetRootElement(doc, root_node);

    xmlSetProp(root_node, BAD_CAST "type", BAD_CAST "clientAuthentication");

    xmlNewChild(root_node, NULL, BAD_CAST "secretSignature",BAD_CAST sigBase64);

    root_node = xmlNewChild(root_node, NULL,BAD_CAST "clientInfo", NULL);

    xmlNewTextChild(root_node, NULL, BAD_CAST "nBI",BAD_CAST numBI);
    xmlNewTextChild(root_node, NULL, BAD_CAST "name",BAD_CAST name);
    xmlNewTextChild(root_node, NULL, BAD_CAST "userName",BAD_CAST userName);
    xmlNewTextChild(root_node, NULL, BAD_CAST "hostName",BAD_CAST hostName);
    

    xmlDocDumpMemory(doc, &s, &messageSize);

    if( messageSize + 1 <= messageMaxSize)
    {
        strcpy((char *) message, (char *) s);
        result = messageSize + 1;
    }       
    else
        result = -1;
    free(sigBase64);
   xmlFree(s);
    xmlFreeDoc(doc);
    xmlCleanupParser();

    return result;
}
int 
messageCheckAck(char *messageReceived, int messageSize)
{
    char *path = "/acknowledge";

    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx; 
    xmlXPathObjectPtr xpathObj; 

    xmlInitParser();
    doc = xmlRecoverMemory(messageReceived, messageSize);
    if (doc == NULL) { return -1;}
    
    xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == NULL) { 
        xmlFreeDoc(doc);
        return -1;
    }

    xpathObj = xmlXPathEvalExpression(BAD_CAST path, xpathCtx);
    if(xpathObj->nodesetval->nodeTab == NULL){
        xmlXPathFreeContext(xpathCtx); 
        xmlFreeDoc(doc); 
        return(0);
    }

    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx); 
    xmlFreeDoc(doc);
    xmlCleanupParser();

    return 1;
}
/*Experimental*/
int
messageGetSingleValue(char *messageReceived, int messageSize, char *path, char *value, int valueMaxSize, int decodeB64)
{
    char *tempB64, *temp;  
    int finalSize;
    xmlDocPtr doc = NULL;/* node pointers */
    xmlXPathContextPtr xpathCtx; 
    xmlXPathObjectPtr xpathObj; 

    LIBXML_TEST_VERSION;
    xmlInitParser();
    doc = xmlRecoverMemory(messageReceived, messageSize);
    if (doc == NULL) { return -1;}
    
    xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == NULL) { 
        xmlFreeDoc(doc);
        return -1;
    };

    xpathObj = xmlXPathEvalExpression(BAD_CAST path, xpathCtx);
    if(xpathObj == NULL){
        xmlXPathFreeContext(xpathCtx); 
        xmlFreeDoc(doc); 
        return(-1);
    };


    tempB64 = (char *) xmlXPathCastToString (xpathObj);
    if(decodeB64)
    {
        temp = b64decode((unsigned char *) tempB64, strlen(tempB64) , &finalSize);
        free(tempB64);
    }
    else
    {
        temp = tempB64;
        finalSize = strlen(temp);
    }
        

    if( finalSize + 1 <= valueMaxSize)
    {
        memcpy (value, temp, finalSize);
        value[finalSize] = '\0';
    }       
    else
        finalSize = -1;

    free(temp);
    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx); 
    xmlFreeDoc(doc);
    xmlCleanupParser();

    return finalSize;

}

int 
messagecheckDiffieHellmanResponse(
    char *messageReceived, int messageSize ,char *sessionId, char *seqNumber, DH *dh)
{
    char path [128];

	xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx; 
    xmlXPathObjectPtr xpathObj; 

    xmlInitParser();
    doc = xmlRecoverMemory(messageReceived, messageSize);
    if (doc == NULL) { return -1;}
    
    xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == NULL) { 
        xmlFreeDoc(doc);
        return -1;
    }

    strcpy(path, "/diffie-hellman[@sessionId = '");
    strcat(path, sessionId);
    strcat(path, "' and @type= 'serverParam']");

    xpathObj = xmlXPathEvalExpression(BAD_CAST path, xpathCtx);
    if(xpathObj == NULL){
        xmlXPathFreeContext(xpathCtx); 
        xmlFreeDoc(doc); 
        return(-1);
    }

    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx); 
    xmlFreeDoc(doc);
    xmlCleanupParser();

    return 0;
}
int
messageRemoveElement(char *original, int originalSize, char *path, char *modified, int maxSize)
{
    int messageSize;
    int result;
    xmlChar *s;
    xmlDocPtr doc = NULL;/* node pointers */
    xmlXPathContextPtr xpathCtx; 
    xmlXPathObjectPtr xpathObj;


    xmlInitParser();
    //xmlKeepBlanksDefault(0);
    doc = xmlRecoverMemory(original, originalSize);
    if (doc == NULL) { return -1;}
    
    xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == NULL) { 
        xmlFreeDoc(doc);
        return -1;
    };

    xpathObj = xmlXPathEvalExpression(BAD_CAST path, xpathCtx);
    if(xpathObj == NULL){
        xmlXPathFreeContext(xpathCtx); 
        xmlFreeDoc(doc); 
        return(-1);
    };

    xmlUnlinkNode(xpathObj->nodesetval->nodeTab[0]);
    xmlFreeNode(xpathObj->nodesetval->nodeTab[0]);

    xmlDocDumpMemory(doc, &s, &messageSize);
    if( messageSize + 1 <= maxSize)
    {
        strcpy((char *) modified, (char *) s);
        result = messageSize + 1;
    }       
    else
        result = -1;

    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx); 
    xmlFree(s);
    xmlFreeDoc(doc);
    xmlCleanupParser();

    return result;
}
