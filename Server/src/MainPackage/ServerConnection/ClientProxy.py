import threading
from socket import socket
from IN import AF_INET, SOCK_DGRAM
from xml.dom.minidom import parse
import xpath
import M2Crypto
import base64
import os
import hashlib
from MainPackage.Message.Message import unmarshal, DiffieHellmanRequest,\
    DiffieHellmanResponse, EncryptedMessage, ServerAuthentication, Acknowledge,\
    Command, TearDown, NewSecretRequest, NewSecretResponse, NotAcknowledge,\
    ClientAuthentication, DiffieHellmanRequestDenied
import datetime
from M2Crypto.EVP import Cipher
from MainPackage.Util.Constants import ENC, DEC
import time
from MainPackage.Util import Constants

class ClientProxy(threading.Thread):
    
    def __init__ (self, inQueue, authorizedUsersXMLFile, activeUsers, serverPrivateKey, serverCertificate, caCertificate, serverIP):
        super(ClientProxy, self).__init__()
        self.inQueue = inQueue
        self.udpSocket = socket(AF_INET, SOCK_DGRAM)
        self.authorizedUsersXMLFile = authorizedUsersXMLFile
        self.activeUsers = activeUsers
        self.privateKey = serverPrivateKey
        self.certificate = serverCertificate
        self.caCertificate = caCertificate
        self.serverIP = serverIP
        
    def run(self):
        
        while True:

            
            originalMessage, sendAddress = self.inQueue.get()
            
    
            try:
                parsedMessage = unmarshal(originalMessage[:-1])
            except Exception as e:
                print "Unmarshal failed of: " + originalMessage + ": " + str(e)    
                continue 
            if isinstance(parsedMessage, DiffieHellmanRequest):
                try:
                    messageToSend = self.__diffieHellmanRequestHandler(parsedMessage)
                    print "sent: " + messageToSend   
                    self.udpSocket.sendto(messageToSend, sendAddress)
                except Exception as e:
                    print e
                    
            elif isinstance(parsedMessage, EncryptedMessage):
                sentSeqNumber = parsedMessage.seqNumber
                sessionID = parsedMessage.sessionID
                iv = parsedMessage.iv
                encryptedMessage = parsedMessage.encryptedMessage
                
                diffieHellmanSession = 0
                
                try:
                    prevSeqNumber, mk, sessionKey, expirationDate, _ = self.activeUsers.getDiffieHellmanUser(sessionID)
                    diffieHellmanSession = 1  
                except:
                    try:
                        nBI, prevSeqNumber, sessionKey, expirationDate, _ = self.activeUsers.getSessionEstablishedUser(sessionID)
                    except Exception as e:
                        print str(e)
                        raise e
                        
                if diffieHellmanSession == 1:
                    try:
                        messageToSend = self.__diffieHellmanSessionMessageHandler(sentSeqNumber, sessionID, iv, encryptedMessage, prevSeqNumber, mk, sessionKey, expirationDate)
                        print "sent: " + messageToSend 
                        self.udpSocket.sendto(messageToSend, sendAddress)
                    except Exception as e:
                        print str(e) + "\n it was not possible terminate authentication"
                        continue
                else:
                    try:
                        messageToSend = self.__sessionEstablishedMessageHandler(nBI, sentSeqNumber, sessionID, iv, encryptedMessage, prevSeqNumber, sessionKey, expirationDate)
                        print "sent: " + messageToSend
                        self.udpSocket.sendto(messageToSend, sendAddress)
                    except Exception as e:
                        print str(e)
                        continue
                            
                        
    def __diffieHellmanRequestHandler(self, parsedMessage):
        seqNumber = parsedMessage.seqNumber  
        oldSessionID = parsedMessage.sessionID
        
        sessionIDSigned = self.__signMessage(oldSessionID)
        
        try:
            self.activeUsers.getDiffieHellmanUser(oldSessionID)
            diffieHellmanRequestDenied = DiffieHellmanRequestDenied(seqNumber, oldSessionID, sessionIDSigned, self.certificate)    
            return diffieHellmanRequestDenied.creatXMLMessage()
        except:
            # this sessionID already exists
            pass

          
        p = parsedMessage.p
        g = parsedMessage.g
        b, mk = self.__generateDH_B_MasterKey(p, g, parsedMessage.a)
        
        sessionID = self.activeUsers.generateSessionID()
        
        secretSignature = self.__signMessage(str(base64.b64decode(str(mk))))
        
        sessionKey = hashlib.sha1(self.__generateSymmetricKey()).hexdigest()
        expirationDate = self.__generateExpirationDate(1) #5min
        authentication = ServerAuthentication(secretSignature, sessionID, sessionKey, expirationDate, self.certificate, self.serverIP, Constants.UDP_PORT)
        tokenSignature = self.__signMessage(authentication.getTokenXML())
        
        authentication.tokenSignature = tokenSignature
        iv = self.__generateIV()
        encryptedMessageText = self.__encryptData(base64.b64decode(mk), iv, authentication.creatXMLMessage())
        timmer = time.time()
        newSeqNumber = self.__encryptData(base64.b64decode(mk), iv, seqNumber)

        diffieHellmanResponse = DiffieHellmanResponse(newSeqNumber, oldSessionID, iv, p, g, b, encryptedMessageText)
        diffieHellmanResponseXML = diffieHellmanResponse.creatXMLMessage()
         
        self.activeUsers.addDiffieHellmanUser(sessionID, seqNumber, mk, sessionKey, expirationDate, timmer)
        
        return diffieHellmanResponseXML
    
            
    def __diffieHellmanSessionMessageHandler(self, sentSeqNumber, sessionID, iv, encryptedMessage, prevSeqNumber, mk, sessionKey, expirationDate):
        
        iv = base64.b64decode(iv)
        self.__verifyExpirationDate(expirationDate)
        decryptedMessage = self.__decryptData(sessionKey, iv, encryptedMessage)
        sentSeqNumber = self.__decryptData(sessionKey, iv, sentSeqNumber)
        
        
        try:
            lastSeqNumber = self.activeUsers.getDiffieHellmanUserLastSeqNumber(sessionID)
        except Exception as e:
            raise e
        
        if lastSeqNumber > sentSeqNumber:
            raise Exception("Wrong SeqNumber")
        
        try:
            parsedMessage = unmarshal(decryptedMessage[:-1])
            iv = self.__generateIV()
            newSeqNumber = self.__encryptData(sessionKey, iv, sentSeqNumber)
        except Exception as e:
            raise Exception("Unmarshal failed of: " + str(decryptedMessage) +": " + str(e))  
        
        if isinstance(parsedMessage, ClientAuthentication):
            secretSignature = parsedMessage.secretSignature
            nBI = parsedMessage.nBI
            name = parsedMessage.name
            userName = parsedMessage.userName
            hostName = parsedMessage.hostName
            
            
            publicKey = self.__userRSAPublicKey(nBI)
            self.__verifySignature(base64.b64decode(mk), publicKey, secretSignature)
                       
            timmer = time.time()
            
            
            self.activeUsers.addSessionEstablishedUser(nBI, name, userName, hostName, sessionID, sentSeqNumber, sessionKey, expirationDate, timmer)
            
            ack = Acknowledge()
            ackXML = ack.creatXMLMessage()
            
           
            encryptedMessageText = self.__encryptData(sessionKey, iv, ackXML)
            encryptedMessage = EncryptedMessage(newSeqNumber, sessionID, iv, encryptedMessageText)    

        else:
            notAck = NotAcknowledge()
            encryptedMessageText = self.__encryptData(sessionKey, iv, notAck.creatXMLMessage())
            encryptedMessage = EncryptedMessage(newSeqNumber, sessionID, iv, encryptedMessageText)
            
        return encryptedMessage.creatXMLMessage()
    
    def __sessionEstablishedMessageHandler(self, nBI, sentSeqNumber, sessionID, iv, encryptedMessage, prevSeqNumber, sessionKey, expirationDate):
        iv = base64.b64decode(iv)
        decryptedMessage = self.__decryptData(sessionKey, iv, encryptedMessage)
        sentSeqNumber = self.__decryptData(sessionKey, iv, sentSeqNumber)
        
        try:
            lastSeqNumber = self.activeUsers.getSessionEstablishedUserLastSeqNumber(sessionID)
        except Exception as e:
            raise e
        
        if lastSeqNumber > sentSeqNumber:
            raise Exception("Wrong SeqNumber")
        
        try:
            parsedMessage = unmarshal(decryptedMessage[:-1])
            iv = self.__generateIV()
            newSeqNumber = self.__encryptData(sessionKey, iv, sentSeqNumber)
        except Exception as e:
            raise Exception("Unmarshal failed: " + str(e))  
        
        if isinstance(parsedMessage, Command):
            self.__verifyExpirationDate(expirationDate)
            date = parsedMessage.date
            command = parsedMessage.command
            
            self.activeUsers.addCommand(sessionID, date, command)
            self.activeUsers.updateTimmerSessionEstablishedUsers(sessionID)
            self.activeUsers.updateSeqNumberSessionEstablishedUsers(sessionID, sentSeqNumber)
            
            ack = Acknowledge()
            ackXML = ack.creatXMLMessage()
            
            encryptedMessageText = self.__encryptData(sessionKey, iv, ackXML)
            
            encryptedMessage = EncryptedMessage(newSeqNumber, sessionID, iv, encryptedMessageText)   
        
        elif isinstance(parsedMessage, TearDown):
            self.__verifyExpirationDate(expirationDate)
            try:
                self.activeUsers.removeSessionEstablished(sessionID)
                ack = Acknowledge()
                ackXML = ack.creatXMLMessage()
                
                encryptedMessageText = self.__encryptData(sessionKey, iv, ackXML)
                encryptedMessage = EncryptedMessage(newSeqNumber, sessionID, iv, encryptedMessageText)   
            except:
                notAck = NotAcknowledge()
                encryptedMessageText = self.__encryptData(sessionKey, iv, notAck.creatXMLMessage())
                encryptedMessage = EncryptedMessage(newSeqNumber, sessionID, iv, encryptedMessageText)

            
        
        elif isinstance(parsedMessage, NewSecretRequest):
            newSessionKey = hashlib.sha1(self.__generateSymmetricKey()).hexdigest()
            newExpirationDate = self.__generateExpirationDate(5) #5min
            
            newSessionKeyResponse = NewSecretResponse(sessionID, newSessionKey, newExpirationDate, self.certificate, self.serverIP, Constants.UDP_PORT)
            tokenSignature = self.__signMessage(newSessionKeyResponse.getTokenXML())
            newSessionKeyResponse.tokenSignature = tokenSignature
            
            print "new sessionkey: " + newSessionKeyResponse.creatXMLMessage()
            
            encryptedMessageText = self.__encryptData(sessionKey, iv, newSessionKeyResponse.creatXMLMessage())
            
            self.activeUsers.updateSessionEstablishedUsers(sessionID, sentSeqNumber, newSessionKey, newExpirationDate)
            
            encryptedMessage = EncryptedMessage(newSeqNumber, sessionID, iv, encryptedMessageText)
            
        else:
            notAck = NotAcknowledge()
            encryptedMessageText = self.__encryptData(sessionKey, iv, notAck.creatXMLMessage())
            encryptedMessage = EncryptedMessage(newSeqNumber, sessionID, iv, encryptedMessageText)

        return encryptedMessage.creatXMLMessage()
          

    def __generateExpirationDate(self, min):
        dt = datetime.datetime.now()
        delta = datetime.timedelta(minutes = min)
        return dt + delta
    
    def __verifyExpirationDate(self, expirationDate):
        delta = datetime.timedelta(minutes = 5)
        now = datetime.datetime.now() 
        
        if expirationDate + delta < now:
            raise Exception("The key expired")
        
    def __generateDH_B_MasterKey(self, p, g, a):
        dh = M2Crypto.DH.set_params(M2Crypto.m2.bn_to_mpi(M2Crypto.m2.hex_to_bn(base64.b64decode(p))), M2Crypto.m2.bn_to_mpi(M2Crypto.m2.hex_to_bn(base64.b64decode(g))))
        dh.gen_key() #generates b and key
        b = dh.pub #B
        mk = dh.compute_key(M2Crypto.m2.bn_to_mpi(M2Crypto.m2.hex_to_bn(base64.b64decode(a))))
        return (base64.b64encode(M2Crypto.m2.bn_to_hex(M2Crypto.m2.mpi_to_bn(b))), base64.b64encode(mk))            
    
    def __userRSAPublicKey(self, nBI):
        doc = parse(self.authorizedUsersXMLFile)
        certificate = None
        try:
            certificate = xpath.find("/users/user/certificate[../nBI/text()='" + nBI + "']", doc)[0].firstChild.nodeValue
            certificate = M2Crypto.X509.load_cert_string(str(certificate))
        except Exception as e:
            raise Exception("This user is not authorized")
        
                       
        publicKey = certificate.get_pubkey().get_rsa()
        
        return publicKey
    
    def __encryptData(self, key, iv, data):
        data = str(data) + '\0'  # <---- ----------
        cipher = Cipher('aes_256_cbc', key, iv, ENC)
        v = cipher.update(data)
        v = v + cipher.final()
        v = base64.b64encode(v)
        return v
        
    def __decryptData(self, key, iv, data):
        data = base64.b64decode(data)
        cipher = Cipher('aes_256_cbc', key, iv, DEC)
        v = cipher.update(data)
        v = v + cipher.final()
        return v    
    
    def __createHMACSignature(self, message, base64SymetricKey):
        hmac = M2Crypto.EVP.HMAC(base64.b64decode(base64SymetricKey),'sha1')
        hmac.update(message)
        return base64.b64encode(hmac.digest())
    
    def __generateSymmetricKey(self):
        return os.urandom(86)
    
    def __generateIV(self):
        return base64.b64encode(os.urandom(16))
    
    def __signMessage(self, message):
        digest = hashlib.sha1(message).digest()
        return base64.b64encode(self.privateKey.sign(digest, 'sha1'))
       
    def __verifySignature(self, message, publicKey , signature):
        signature = base64.b64decode(signature)
        digest = hashlib.sha1(message).digest()
        try:
            publicKey.verify(digest, signature, 'sha1')
        except Exception as e:
            raise Exception("The signature doesn't match " + str(e))
        
    def __verifyCertificate(self, certificate):
        caPublicKey = self.caCertificate.get_pubkey()
        return certificate.verify(caPublicKey) == 1
