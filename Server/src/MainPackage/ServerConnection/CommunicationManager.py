import threading
import Queue
from MainPackage.Util.Constants import UDP_PORT, BUFFER_SIZE
from socket import socket
from IN import AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_BROADCAST
import netifaces

class CommunicationManager:
    
    def __init__ (self, inQueue):
        self.udpSocket = socket(AF_INET, SOCK_DGRAM)
        self.udpSocket.bind(('', UDP_PORT))
        self.receiverThread = self.ReceiverThread(self.udpSocket, inQueue, self)
        self.__startCommunications()
        
    def isLocalIP(self, ip):
        interfaces = netifaces.interfaces()
        for i in interfaces:
            if i == 'lo':
                continue
            iface = netifaces.ifaddresses(i).get(netifaces.AF_INET)
            if iface != None:
                for j in iface:
                    if j['addr'] == ip:
                        return True
        return False 
    
    def __startCommunications(self):
        self.receiverThread.start()        

    class ReceiverThread(threading.Thread):
     
        def __init__ (self, socket, queue, communicationManager):
            super(CommunicationManager.ReceiverThread, self).__init__()
            self.udpSocket = socket
            self.queue = queue
            self.communicationManager = communicationManager
            
        def run(self):
            while True:
                packet, (ip, port) = self.udpSocket.recvfrom(BUFFER_SIZE);
                if not self.communicationManager.isLocalIP(ip):
                    self.queue.put((str(packet), (ip, port))) 
                        
    


    
        
