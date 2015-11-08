import threading
from xml.dom.minidom import Document, parse
import xpath
from MainPackage.Util.CreateXMLFiles import addElementToTopElement
import datetime
import time
    

class ActiveUsers:
    
    def __init__ (self, commandsFilePath):
        self.commandsFilePath = commandsFilePath
        self.sessionID = 0
        self.diffieHellmanUsers = {} #self.diffieHellmanUsers[sessionID] = (seqNumber, masterKey, sessionKey, expiratonDate, timmer)
        self.sessionEstablishedUsers = {} # self.sessionEstablishedUsers[sessionID] = (nBI, seqNumber, sessionKey, expiratonDate, timmer)
        self.lock = threading.RLock()
        
    #The user is doing the DIffie Hellman process    
    def addDiffieHellmanUser(self, sessionID, seqNumber, masterKey, sessionKey, expiratonDate, timmer):
        self.lock.acquire()
        
        self.diffieHellmanUsers[sessionID] = (seqNumber, masterKey, sessionKey, expiratonDate, timmer)
        
        self.lock.release()
        
    def getDiffieHellmanUser(self, sessionID):
        self.lock.acquire()
        
        try:
            diffieHelmmanUser = self.diffieHellmanUsers[sessionID]
        except:
            self.lock.release()
            raise Exception("The session doesn't exist")
        
        self.lock.release()
        
        return diffieHelmmanUser

    def getDiffieHellmanUserLastSeqNumber(self, sessionID):
        self.lock.acquire()
        
        try:
            seqNumber, _, _, _, _ = self.diffieHellmanUsers[sessionID]
        except:
            self.lock.release()
            raise Exception("The session doesn't exist")
        
        self.lock.release()
        
        return seqNumber
        
    def getSessionEstablishedUser(self, sessionID):
        self.lock.acquire()
        
        try:
            user = self.sessionEstablishedUsers[sessionID]
        except:
            self.lock.release()
            raise Exception("The active user doesn't exist")
        
        self.lock.release()
        
        return user
    
    def getSessionEstablishedUserLastSeqNumber(self, sessionID):
        self.lock.acquire()
        
        try:
            _, seqNumber, _, _, _ = self.sessionEstablishedUsers[sessionID]
        except:
            self.lock.release()
            raise Exception("The session doesn't exist")
        
        self.lock.release()
        
        return seqNumber   
    
    def addSessionEstablishedUser(self, nBI, name, userName, hostName, sessionID, seqNumber, sessionKey, expirationDate, timmer):
        self.lock.acquire()
        
        now = datetime.datetime.now()
        
        #if already exists
        try:
            doc = parse(nBI + "_" + name + ".xml")
            sessionsElement = doc.documentElement
            sessionElement = doc.createElement("session")
            sessionsElement.appendChild(sessionElement)
            sessionElement.setAttribute("sessionID", sessionID)
            addElementToTopElement(doc, sessionElement, "date", str(now))
            addElementToTopElement(doc, sessionElement, "userName", userName)
            addElementToTopElement(doc, sessionElement, "hostName", hostName)
            xmlFile = open(nBI + "_" + name + ".xml", "w")
            doc.writexml(xmlFile)
            xmlFile.close()    
        except:
            #if not exists
            doc = Document()
            sessionsElement = doc.createElement("sessions")
            doc.appendChild(sessionsElement)
            sessionElement = doc.createElement("session")
            sessionsElement.appendChild(sessionElement)
            sessionElement.setAttribute("sessionID", sessionID)
            addElementToTopElement(doc, sessionElement, "date", str(now))
            addElementToTopElement(doc, sessionElement, "userName", userName)
            addElementToTopElement(doc, sessionElement, "hostName", hostName)
            xmlFile = open(nBI + "_" + name + ".xml", "w")
            doc.writexml(xmlFile)
            xmlFile.close()
            
        try:
            self.__addSessionToCommandFile(nBI, sessionID, str(now))
        except Exception as e:
            self.lock.release()
            raise e
                    
        
        try:
            self.diffieHellmanUsers.pop(sessionID)
            self.sessionEstablishedUsers[sessionID] = (nBI, seqNumber, sessionKey, expirationDate, timmer)    
        except:
            self.lock.release()
            raise Exception("It was not possible add the new user to the the active users set because DH process was not done before")       
        
        self.lock.release()
        
    def __addSessionToCommandFile(self, nBI, sessionID, initDate):
        
        try:
            doc = parse(self.commandsFilePath)
            node = xpath.find("/commandsLog/user[@nBI='" + nBI + "']", doc)
    
            if len(node) > 0:
                userElement = node[0]
                sessionElement = doc.createElement("session")
                userElement.appendChild(sessionElement)
                sessionElement.setAttribute("sessionID", sessionID)
                sessionElement.setAttribute("sessionStart", initDate)
                sessionElement.setAttribute("sessionEnd", "")
    
            else:
                topElement = xpath.find("/commandsLog", doc)[0]
                newElement = doc.createElement("user")
                topElement.appendChild(newElement)
                newElement.setAttribute("nBI", nBI)
                sessionElement = doc.createElement("session")
                newElement.appendChild(sessionElement)
                sessionElement.setAttribute("sessionID", sessionID)
                sessionElement.setAttribute("sessionStart", initDate)
                sessionElement.setAttribute("sessionEnd", "")
                
            self.__writeToXMLFile(doc)
        except:
            raise Exception("It was not possible to add the user to de command file")  
    
        
    def removeSessionEstablished(self, sessionID):
        self.lock.acquire()
        
        try:
            nBI, _, _, _, _ = self.sessionEstablishedUsers[sessionID]
            self.__updateSessionEnd(nBI, sessionID, str(datetime.datetime.now()))
            self.sessionEstablishedUsers.pop(sessionID)
        except:
            self.lock.release()
            raise Exception("The user it's not active")
        
        self.lock.release()
        
    def __updateSessionEnd(self, nBI, sessionID, endDate):
        try:
            doc = parse(self.commandsFilePath)
            node = xpath.find("/commandsLog/user/session[../@nBI='" + nBI + "' and @sessionID='" + sessionID + "']", doc)
            if len(node) > 0:
                userElement = node[0]
                userElement.setAttribute("sessionEnd", endDate)
                self.__writeToXMLFile(doc)
            else:
                raise Exception()
        except:
            raise Exception("It was not possible to update the end date")  
        
        
    def addCommand(self, sessionID, date, command):
        self.lock.acquire()
        
        nBI, _, _, _, _ = self.sessionEstablishedUsers[sessionID]
        
        doc = parse(self.commandsFilePath)
        sessionNode = xpath.find("/commandsLog/user/session[../@nBI='" + nBI + "' and @sessionID='" + sessionID + "']", doc)
        
        if len(sessionNode) > 0:
            sessionElememt = sessionNode[0]
            commandElement = doc.createElement("command")
            sessionElememt.appendChild(commandElement)
            commandElement.setAttribute("date", date)
            text = doc.createTextNode(command)
            commandElement.appendChild(text)
            self.__writeToXMLFile(doc)
        else:
            self.lock.release()
            raise Exception("This session doesn't exist in xml file")
        
        self.lock.release()
        
    def updateTimmerSessionEstablishedUsers(self, sessionID):
        self.lock.acquire()
        
        try: 
            nBI, seqNumber, sessionKey, expirationDate, _ = self.sessionEstablishedUsers[sessionID]
            timmer = time.time()
            self.sessionEstablishedUsers[sessionID] = (nBI, seqNumber, sessionKey, expirationDate, timmer)
        except:
            self.lock.release()
            raise Exception("The user it's not active")
        
        self.lock.release()
        
    def updateSessionEstablishedUsers(self, sessionID, seqNumber, sessionKey, expirationDate):
        self.lock.acquire()
        
        try: 
            nBI, _, _, _, _ = self.sessionEstablishedUsers[sessionID]
            timmer = time.time()
            self.sessionEstablishedUsers[sessionID] = (nBI, seqNumber, sessionKey, expirationDate, timmer)
        except:
            self.lock.release()
            raise Exception("The user it's not active")
        
        self.lock.release()     
        
    def updateSeqNumberSessionEstablishedUsers(self, sessionID, sentSeqNumber):
        self.lock.acquire()
        
        try:   
            nBI, _, sessionKey, expiratonDate, timmer = self.sessionEstablishedUsers[sessionID]
            timmer = time.time()
            self.sessionEstablishedUsers[sessionID] = (nBI, sentSeqNumber, sessionKey, expiratonDate, timmer)
        except:
            self.lock.release()
            raise Exception("The user it's not active")
        
        self.lock.release()

    def verifyInactiveSessions(self):
        self.lock.acquire()
        
        iterator = self.sessionEstablishedUsers.iterkeys()
        
        for session in iterator:
            _, _, _, _, timmer = self.sessionEstablishedUsers[session]
            if time.time() - timmer > 60 * 60:
                self.sessionEstablishedUsers.pop(session)
                
                
        iterator = self.diffieHellmanUsers.iterkeys()
        
        for session in iterator:                
                
            _, _, _, _, timmer = self.diffieHellmanUsers[session]
            if time.time() - timmer > 60 * 60:
                self.diffieHellmanUsers.pop(session)                

        self.lock.release()
        
    def generateSessionID(self):
        self.lock.acquire()
        
        if self.sessionID == 4294967295:
            self.sessionID = 1
        else:
            self.sessionID += 1
            
        return str(self.sessionID)
        
        self.lock.release()          
        
        
    def __writeToXMLFile(self, document):
        xmlFile = open(self.commandsFilePath, "w")
        document.writexml(xmlFile)
        xmlFile.close()
        
    
                       
