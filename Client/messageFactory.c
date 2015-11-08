#include <mxml.h>
#include <string.h>

int logInMessage(
	char *nBI, 
	char *name, 
	char *hostName, 
	char *message,
	int size)
{
	mxml_node_t *xDoc;
	mxml_node_t *messageNode;
	mxml_node_t *innerNode[4];

	xDoc = mxmlNewXML("1.0");
	messageNode = mxmlNewElement(xDoc, "message");

	innerNode[0] = mxmlNewElement(messageNode, "type");
	mxmlNewText(innerNode[0], 0, "Login");

	innerNode[1] = mxmlNewElement(messageNode, "nBI");
	mxmlNewText(innerNode[1], 0, nBi);

	innerNode[2] = mxmlNewElement(messageNode, "name");
	mxmlNewText(innerNode[2], 0, name);

	innerNode[3] = mxmlNewElement(messageNode, "hostName");
	mxmlNewText(innerNode[3], 0, hostName);

	mxmlSaveString (xDoc, message, size, MXML_NO_CALLBACK);

	mxmlDelete(xDoc);

	return 0;
}

int challengeResponseMessage(
	char *challResp, 
	char *message,
	int size)
{
	mxml_node_t *xDoc;
	mxml_node_t *messageNode;
	mxml_node_t *innerNode[2];

	xDoc = mxmlNewXML("1.0");
	messageNode = mxmlNewElement(xDoc, "message");

	innerNode[0] = mxmlNewElement(messageNode, "type");
	mxmlNewText(innerNode[0], 0, "ChallengeResponse");

	innerNode[1] = mxmlNewElement(messageNode, "ChallengeResponse");
	mxmlNewText(innerNode[1], 0, challResp);

	mxmlSaveString (xDoc, message, size, MXML_NO_CALLBACK);

	mxmlDelete(xDoc);

	return 0;
}

int command(
	char *nBI, 
	char *command, 
	char *message,
	int size)
{
	mxml_node_t *xDoc;
	mxml_node_t *messageNode;
	mxml_node_t *innerNode[2];

	xDoc = mxmlNewXML("1.0");
	messageNode = mxmlNewElement(xDoc, "message");

	innerNode[0] = mxmlNewElement(messageNode, "type");
	mxmlNewText(innerNode[0], 0, "Command");

	innerNode[1] = mxmlNewElement(messageNode, "Command");
	mxmlNewText(innerNode[1], 0, command);

	mxmlSaveString (xDoc, message, size, MXML_NO_CALLBACK);

	mxmlDelete(xDoc);

	return 0;
}
int tearDown(char *nBI, char *message, int size)
{
	mxml_node_t *xDoc;
	mxml_node_t *messageNode;
	mxml_node_t *innerNode[2];

	xDoc = mxmlNewXML("1.0");
	messageNode = mxmlNewElement(xDoc, "message");

	innerNode[0] = mxmlNewElement(messageNode, "type");
	mxmlNewText(innerNode[0], 0, "TearDown");

	innerNode[1] = mxmlNewElement(messageNode, "nBI");
	mxmlNewText(innerNode[1], 0, nBi);

	mxmlSaveString (xDoc, message, size, MXML_NO_CALLBACK);

	mxmlDelete(xDoc);

	return 0;
}
int addSignature(
	char *unsignedMessage, 
	char *signature,
	char *signedMessage,
	int size)
{
	mxml_node_t *xDoc;
	mxml_node_t *messageNode;
	mxml_node_t *innerNode;

	xDoc = mxmlLoadString( NULL, unsignedMessage, MXML_NO_CALLBACK);
	messageNode = mxmlGetFirstChild(xDoc);

	innerNode = mxmlNewElement(messageNode, "signature");
	mxmlNewText(innerNode, 0, signature); //por em base64

	---PROVOCARE ERRO ____ base64

	mxmlSaveString (xDoc, message, size, MXML_NO_CALLBACK);

	mxmlDelete(xDoc);
}
