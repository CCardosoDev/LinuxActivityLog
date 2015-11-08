from xml.dom.minidom import Document, parse, parseString
import xpath
import M2Crypto
import base64
import hashlib
import datetime
import os
from MainPackage.Util.Constants import ENC, DEC
import M2Crypto
import socket
import time


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
    
def signMessage(message, privateKey):
        digest = hashlib.sha1(message).digest()
        return base64.b64encode(privateKey.sign(digest, 'sha1'))
       
def verifySignature(message, publicKey , signature):
        signature = base64.b64decode(signature)
        digest = hashlib.sha1(message).digest()
        try:
            if publicKey.verify(digest, signature, 'sha1') :
                print "ok"
        except Exception as e:
            raise Exception("The signature doesn't match " + str(e)) 

delta = datetime.timedelta(minutes = 5)
print delta
now = datetime.datetime.now()
print now
print now + delta


'''
privateKey = M2Crypto.RSA.load_key("../Certificates/MainServer.pem")

s = str("iggUqdOOYNmBVmK6jUb7jQeLNe9E1SytY/k5bbAa6JA=")

signature = "AAAAAEQAAAD0f1a3AQAAAAEAAABM3pAInR1Dt/jXkAgAAgAAINSQCPjXkAj415AIOxJRtyAAAAB4yii3AGQ5tzsSUbd03pAI/////yDUkAjA2ZAImNmQCAACAABg3pAICAAAACAAAAAQAAAAdN6QCAQAAAAcAAAA+P///yAAAAA7ElG3UAEAAPR/Vrfw05AI/ZBvt4UcP7eakQQION6QCC33b7cCAAAA9O9wt3ghPbcDAAAA2Dy/tqyWb7c7ElG3CAAAAIDZkAjZM0O32Dy/tjsSUbdQAQAA9H9WtxcAAAAWoSaZBQgAAABkObcovz23iN+QCGylcLeoNz23EQAAAAAAAAAAAAAAAQAAAHgIAABYPb+2ABBXt06OBAjoFz63/IMECAEAAAD073C30Ppwt7DF9r+Ixfa/OZlvt3TF9r/8gwQIXMX2v3T6cLcAAAAA"

doc = parse("MainPackage/Util/authorizedUsers.xml")

certificate = None
try:
    certificate = xpath.find("/users/user/certificate[../nBI/text()='" + "137609094" + "']", doc)[0].firstChild.nodeValue
    certificate = M2Crypto.X509.load_cert_string(str(certificate))
except Exception as e:
    raise Exception("This user is not authorized")

               
publicKey = certificate.get_pubkey().get_rsa()

#os.remove("tempFile") #remove the file

verifySignature(s, publicKey, signature)

'''
'''
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(('google.com', 0))
print s.getsockname()[0]
'''

'''

privateKey = M2Crypto.RSA.load_key("../Certificates/MainServer.pem")

s = "ola, esta td bemsfsfsdfsdfsdf?"

digest = hashlib.sha1(s).hexdigest()

signature = privateKey.sign(digest, 'sha1')

selfCertificate = M2Crypto.X509.load_cert("../Certificates/MainServer.pem")

publicKey = selfCertificate.get_pubkey().get_rsa()

verifySignature(s, publicKey, base64.b64encode(signature))

'''
       


    
'''    
dt = datetime.datetime.now()
delta = datetime.timedelta(minutes = 1)
print dt + delta

sessionKey = hashlib.sha1("ola").hexdigest()
iv = base64.b64encode(os.urandom(16))
cipher = Cipher('aes_256_cbc', sessionKey, iv, ENC)
v = cipher.update("ola bom dia!! :)")
v = v + cipher.final()
v = base64.b64encode(v)

data = base64.b64decode(v)
cipher = Cipher('aes_256_cbc', sessionKey, iv, DEC)
v = cipher.update(data)
v = v + cipher.final()
print v
'''
   
    
'''  
dh = M2Crypto.DH.gen_params(256, DH_GENERATOR_2)
print dh.p
print dh.g
dh.gen_key() #generates a and key
a = dh.pub #a

dh2 = M2Crypto.DH.set_params(dh.p, dh.g)
dh2.gen_key() #generates b and key
b = dh2.pub #b

print dh.compute_key(b)

print dh2.compute_key(a)

print hashlib.sha1(dh2.compute_key(a)).hexdigest()
'''
  
'''
try:
    doc = parse("13711945_Name.xml")
    sessionsElement = doc.documentElement
    sessionElement = doc.createElement("session")
    sessionsElement.appendChild(sessionElement)
    sessionElement.setAttribute("sessionID", "2")
    addElementToTopElement(doc, sessionElement, "date", "date2")
    addElementToTopElement(doc, sessionElement, "userName", "userName2")
    addElementToTopElement(doc, sessionElement, "hostName", "hostName2")
    xmlFile = open("13711945_Name.xml", "w")
    doc.writexml(xmlFile)
    xmlFile.close()    
except:
    print "exception"
    doc = Document()
    sessionsElement = doc.createElement("sessions")
    doc.appendChild(sessionsElement)
    sessionElement = doc.createElement("session")
    sessionsElement.appendChild(sessionElement)
    sessionElement.setAttribute("sessionID", "1")
    addElementToTopElement(doc, sessionElement, "date", "date")
    addElementToTopElement(doc, sessionElement, "userName", "userName")
    addElementToTopElement(doc, sessionElement, "hostName", "hostName")
    xmlFile = open("13711945_Name.xml", "w")
    doc.writexml(xmlFile)
    xmlFile.close()
   ''' 
''' 
doc = Document()
authElement = doc.createElement("authentication")
doc.appendChild(authElement)
newElemt = doc.createElement("teste")
authElement.appendChild(newElemt)
newElemt2 = doc.createElement("teste2")
newElemt.appendChild(newElemt2)
text = doc.createTextNode("ola")
newElemt2.appendChild(text)
authElement.setAttribute("type", "serverAuth")

print doc.documentElement.toxml()
'''

'''
topElement = doc.documentElement.nodeName
print len(topElement)
print authElement.getElementsByTagName("teste2")[0].firstChild.nodeValue
print xpath.find("/authentication/teste", doc)[0].firstChild.nodeValue

teste =  {}

teste["23"] = "ola"

print teste["2"]

'''
    
'''
pubKey = "-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCjpcWauPV2Kr/6DoskraJu4SCtXf454CQhN467hpPkGJtC3hrlahsf02nnF0b0nxg5tQWdEPAa1YT5eOknvspOot+AwoTzPWusflx1BCIDCiU0y2Yu98bbrD7aLAIqj8u2KkyjhQlt6nOB9MNMsFwTkwfwWCMvYv8zcD8BMDPAwQIDAQAB-----END PUBLIC KEY-----"

pubKey2 = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCjpcWauPV2Kr/6DoskraJu4SCt\nXf454CQhN467hpPkGJtC3hrlahsf02nnF0b0nxg5tQWdEPAa1YT5eOknvspOot+A\nwoTzPWusflx1BCIDCiU0y2Yu98bbrD7aLAIqj8u2KkyjhQlt6nOB9MNMsFwTkwfw\nWCMvYv8zcD8BMDPAwQIDAQAB\n-----END PUBLIC KEY-----"

doc = parse("../authorizedUsers.xml")
pubKeyFile = xpath.find("/users/user/publicKey[../nBI/text()='" + "137119453" + "']", doc)[0].firstChild.nodeValue

pubkey = "-----BEGIN PUBLIC KEY-----\n" + pubKeyFile[0:64] + "\n" + pubKeyFile[64:128] + "\n" + pubKeyFile[128:192] + "\n" + pubKeyFile[192:] +" \n-----END PUBLIC KEY-----"

fil = file("test", "w")
fil.write(pubkey)
fil.close()

pubKeyFile = M2Crypto.RSA.load_pub_key("test")
'''
'''
keyPar = M2Crypto.RSA.gen_key(1024, 65537)

keyPar.save_pub_key("test")

s = str("CNRap1ZCwzanm4vd/CtnjGMmjdDn/0ceUbxskJlr2N8=")

signature = signMessage(s, keyPar.privateKey)

publicKey = M2Crypto.RSA.load_pub_key("tempFile")

#os.remove("tempFile") #remove the file

verifySignature(s, publicKey, signature)


#pubKey = M2Crypto.RSA.load_key_string(pubKey2)

#print pubKeyFile
'''
   
'''
doc = Document()
topElement = doc.createElement("users")
doc.appendChild(topElement)

newElement = doc.createElement("user")
topElement.appendChild(newElement)


addElement(doc, "user", "nBI", "13711945")
addElement(doc, "user", "publicKey", "123456789")


xmlFile = open("test.xml", "w")
doc.writexml(xmlFile)
xmlFile.close()

doc = parse("test.xml")
topElement = doc.getElementsByTagName("users")[0]

newElement = doc.createElement("user")
topElement.appendChild(newElement)



addElementToTopElement(doc, newElement, "nBI", "123456789")
addElementToTopElement(doc, newElement, "publicKey", "987654321")

xmlFile = open("test.xml", "w")
doc.writexml(xmlFile)
xmlFile.close()
'''




