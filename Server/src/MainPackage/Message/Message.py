from  xml.dom.minidom import Document, parseString
import base64
import time

#messages during diffie-hellmen

class DiffieHellmanRequest:
    def __init__(self, seqNumber, sessionID, p, g, a):
        self.seqNumber = seqNumber
        self.sessionID = sessionID
        self.g = g
        self.p = p
        self.a = a
        
class DiffieHellmanResponse:
    def __init__(self, seqNumber, sessionID, iv, p, g, b, encryptedMessageText):
        self.seqNumber = seqNumber
        self.sessionID = sessionID
        self.iv = iv
        self.g = g
        self.p = p
        self.b = b
        self.encryptedMessageText = encryptedMessageText
        
    def creatXMLMessage(self):
        doc = Document()
        topElement = doc.createElement("diffie-hellman")
        doc.appendChild(topElement)
        topElement.setAttribute("session", self.sessionID)
        topElement.setAttribute("type", "serverParam")
        addElementToTopElement(doc, topElement, "p", self.p)
        addElementToTopElement(doc, topElement, "g", self.g)
        addElementToTopElement(doc, topElement, "B", self.b)
        encryElement = doc.createElement("encryptedMessage")
        topElement.appendChild(encryElement)
        encryElement.setAttribute("seqNumber", self.seqNumber)
        encryElement.setAttribute("session", self.sessionID)
        encryElement.setAttribute("iv", self.iv)
        text = doc.createTextNode(self.encryptedMessageText)
        encryElement.appendChild(text)

        return doc.toxml()
    
class DiffieHellmanRequestDenied:
    def __init__(self, seqNumber, sessionID, signature, certificate):
        self.seqNumber = seqNumber
        self.sessionID = sessionID
        self.signature = signature
        self.certificate = certificate
        
    def creatXMLMessage(self):
        doc = Document()
        topElement = doc.createElement("requestDinied")
        doc.appendChild(topElement)
        topElement.setAttribute("session", self.sessionID)
        topElement.setAttribute("seqNumber", self.seqNumber)
        addElementToTopElement(doc, topElement, "signature", self.signature)
        addElementToTopElement(doc, topElement, "certificate", str(self.certificate.as_pem()))
        return doc.toxml()

#messages after diffie-helmen
class EncryptedMessage:
    def __init__(self, seqNumber, sessionID, iv, encryptedMessage):
        self.seqNumber = seqNumber
        self.sessionID = sessionID
        self.iv = iv
        self.encryptedMessage = encryptedMessage
        
    def creatXMLMessage(self):
        doc = Document()
        topElement = doc.createElement("encryptedMessage")
        doc.appendChild(topElement)
        topElement.setAttribute("seqNumber", self.seqNumber)
        topElement.setAttribute("session", self.sessionID)
        topElement.setAttribute("iv", self.iv)
        text = doc.createTextNode(self.encryptedMessage)
        topElement.appendChild(text)
        return doc.toxml()
            
class Acknowledge: 
    def creatXMLMessage(self):
        doc = Document()
        topElement = doc.createElement("acknowledge")
        doc.appendChild(topElement)
        return doc.toxml()

class NotAcknowledge:
    def creatXMLMessage(self):
        doc = Document()
        topElement = doc.createElement("notAcknowledge")
        doc.appendChild(topElement)
        return doc.toxml()

class TearDown: 
    pass

class NewSecretRequest:
    pass
    
class NewSecretResponse:
    def __init__(self, sessionID, sessionKey, expirationDate, serverCertificate, serverIP = None, serverPort = None, tokenSignature = None):
        self.sessionID = sessionID
        self.sessionKey = sessionKey
        self.expirationDate = dateToEpoch(expirationDate)
        self.serverCertificate = serverCertificate
        self.tokenSignature = tokenSignature
        self.serverIP = serverIP
        self.serverPort = serverPort
        
    def creatXMLMessage(self):
        doc = Document()
        topElement = doc.createElement("newSessionKey")
        doc.appendChild(topElement)
        topElement.setAttribute("type", "response")
        if self.tokenSignature != None:
            addElementToTopElement(doc, topElement, "tokenSignature", self.tokenSignature)
        else:
            tokenSignature = doc.createElement("tokenSignature")
            topElement.appendChild(tokenSignature)
        clientTokenElement = doc.createElement("clientTokenB64")
        topElement.appendChild(clientTokenElement)
        text = doc.createTextNode(base64.b64encode(self.getTokenXML()))
        clientTokenElement.appendChild(text)
        return doc.toxml()
   
    def getTokenXML(self):
        doc = Document()
        clientTokenElement = doc.createElement("clientToken")
        doc.appendChild(clientTokenElement)
        clientTokenElement.setAttribute("session", self.sessionID)
        sessionKeyElement = doc.createElement("sessionKey")
        clientTokenElement.appendChild(sessionKeyElement)
        text = doc.createTextNode(self.sessionKey)
        sessionKeyElement.appendChild(text)
        addElementToTopElement(doc, clientTokenElement, "expirationDate", self.expirationDate)
        addElementToTopElement(doc, clientTokenElement, "serverCertificate", str(self.serverCertificate.as_pem()))
        addElementToTopElement(doc, clientTokenElement, "serverIP", str(self.serverIP))
        addElementToTopElement(doc, clientTokenElement, "serverPort", str(self.serverPort))
        return doc.toxml()    

class Command:
    def __init__(self, date, command):
        self.date = epochToDate(float(date))
        self.command = command

class ClientAuthentication:
    def __init__(self, secretSignature, nBI, name, userName, hostName):
        self.secretSignature = secretSignature
        self.nBI = nBI
        self.name = name
        self.userName = userName
        self.hostName = hostName
        
class ServerAuthentication:
    def __init__(self, secretSignature, sessionID, sessionKey, expirationDate, serverCertificate, serverIP = None, serverPort = None, tokenSignature = None):
        self.secretSignature = secretSignature
        self.sessionID = sessionID
        self.sessionKey = sessionKey
        self.expirationDate = dateToEpoch(expirationDate)
        self.serverCertificate = serverCertificate
        self.tokenSignature = tokenSignature
        self.serverIP = serverIP
        self.serverPort = serverPort
        
    def creatXMLMessage(self):
        doc = Document()
        topElement = doc.createElement("authentication")
        doc.appendChild(topElement)
        topElement.setAttribute("type", "serverAuthentication")
        sessionSignatureElement = doc.createElement("secretSignature")
        topElement.appendChild(sessionSignatureElement)
        text = doc.createTextNode(self.secretSignature)
        sessionSignatureElement.appendChild(text)
        
        if self.tokenSignature != None:
            addElementToTopElement(doc, topElement, "tokenSignature", self.tokenSignature)
        else:
            tokenSignature = doc.createElement("tokenSignature")
            topElement.appendChild(tokenSignature)
        
        clientTokenElement = doc.createElement("clientTokenB64")
        topElement.appendChild(clientTokenElement)
        text = doc.createTextNode(base64.b64encode(self.getTokenXML()))
        clientTokenElement.appendChild(text)
        return doc.toxml()
    
    def getTokenXML(self):
        doc = Document()
        clientTokenElement = doc.createElement("clientToken")
        doc.appendChild(clientTokenElement)
        clientTokenElement.setAttribute("session", self.sessionID)
        sessionKeyElement = doc.createElement("sessionKey")
        clientTokenElement.appendChild(sessionKeyElement)
        text = doc.createTextNode(self.sessionKey)
        sessionKeyElement.appendChild(text)
        addElementToTopElement(doc, clientTokenElement, "expirationDate", self.expirationDate)
        addElementToTopElement(doc, clientTokenElement, "serverCertificate", str(self.serverCertificate.as_pem()))
        addElementToTopElement(doc, clientTokenElement, "serverIP", str(self.serverIP))
        addElementToTopElement(doc, clientTokenElement, "serverPort", str(self.serverPort))

        
        return doc.toxml() 
    
        
def unmarshal(message):

    doc = parseString(message)
    print "received: " + doc.toxml()
    topElement = doc.documentElement
    
    messageFamily = topElement.nodeName
    
    if messageFamily == "encryptedMessage":
        seqNumber = topElement.getAttribute("seqNumber")
        if len(seqNumber) == 0:
            raise Exception("Wrong message")
        sessionID = topElement.getAttribute("session")
        if len(sessionID) == 0:
            raise Exception("Wrong message")
        iv = topElement.getAttribute("iv")
        if len(iv) == 0:
            raise Exception("Wrong message")
        encryptedMessage = str(getElementTextFromString(message, "encryptedMessage"))
        if len(encryptedMessage) == 0:
            raise Exception("Wrong message")
        return EncryptedMessage(seqNumber, sessionID, iv, encryptedMessage)
    
    elif messageFamily == "diffie-hellman":
        seqNumber = topElement.getAttribute("seqNumber")
        if len(seqNumber) == 0:
            raise Exception("Wrong message")
        sessionID = topElement.getAttribute("session")
        if len(sessionID) == 0:
            raise Exception("Wrong message")
        p = str(getElementTextFromString(message, "p"))
        if len(p) == 0:
            raise Exception("Wrong message")
        g = str(getElementTextFromString(message, "g"))
        if len(g) == 0:
            raise Exception("Wrong message")
        a = str(getElementTextFromString(message, "A"))
        if len(a) == 0:
            raise Exception("Wrong message")
        return DiffieHellmanRequest(seqNumber, sessionID, p, g, a)
    
    elif messageFamily == "tearDown":
        return TearDown()
    
    elif messageFamily == "newSessionKey":
        return NewSecretRequest()
    
    elif messageFamily == "command":
        date = topElement.getAttribute("date")
        if len(date) == 0:
            raise Exception("Wrong message")
        command = str(getElementTextFromString(message, "command"))
        if len(command) == 0:
            raise Exception("Wrong message")
        return Command(date, command)
    
    elif messageFamily == "authentication":
        secretSignature = str(getElementTextFromString(message, "secretSignature"))
        if len(secretSignature) == 0:
            raise Exception("Wrong message")
        nBI = str(getElementTextFromString(message, "nBI"))
        if len(nBI) == 0:
            raise Exception("Wrong message")
        name = str(getElementTextFromString(message, "name"))
        if len(name) == 0:
            raise Exception("Wrong message")
        userName = str(getElementTextFromString(message, "userName"))
        if len(userName) == 0:
            raise Exception("Wrong message")
        hostName = str(getElementTextFromString(message, "hostName"))
        if len(hostName) == 0:
            raise Exception("Wrong message")
        return ClientAuthentication(secretSignature, nBI, name, userName, hostName)
    
    else:
        raise Exception("Malformed message!")

def addElement(document, topElementName, newElementName, newElementText):
        topElement = document.getElementsByTagName(topElementName)[0]
        newElement = document.createElement(newElementName)
        topElement.appendChild(newElement)
        text = document.createTextNode(newElementText)
        newElement.appendChild(text)
        
def addElementToTopElement(document, topElement, newElementName, newElementText):
    newElement = document.createElement(newElementName)
    topElement.appendChild(newElement)
    text = document.createTextNode(newElementText)
    newElement.appendChild(text)         

def getElementTextFromString(xmlString, elementName):
    root = parseString(xmlString)
    return root.getElementsByTagName(elementName)[0].firstChild.nodeValue

def addSignature(xmlString, signature):
    root = parseString(xmlString)
    addElement(root, "message", "signature", signature)
    return str(root.toxml())

def removeSignature(xmlString):
    root = parseString(xmlString)
    topElement = root.documentElement
    signature = topElement.removeChild(topElement.getElementsByTagName("signature")[0]).firstChild.nodeValue
    return (str(root.toxml()), str(signature))

def dateToEpoch(date):  
    timestamp = int(round(int(date.strftime('%s'))))
    return str(timestamp)

def epochToDate(epoch):
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(epoch))         

