import socket
from MainPackage.ServerConnection.ClientProxy import ClientProxy
import Queue
import argparse
import M2Crypto
from MainPackage.ServerConnection.CommunicationManager import CommunicationManager
from MainPackage.ServerConnection.ActiveUsers import ActiveUsers
from MainPackage.ServerConnection.SessionVerifierThread import SessionVerifierThread
from MainPackage.Util import Constants

parser = argparse.ArgumentParser(description='Authentication server.')

#--privateKey ../../../Certificates/MainServer.pem --selfCertificate ../../../Certificates/MainServer.pem --caCertificate ../../../Certificates/ClaudiaJoao.pem


parser.add_argument("--privateKey", help="private key location", dest="privateKeyFile",  action="store")
parser.add_argument("--selfCertificate", help="self certificate location, PEM file",  dest="selfCertificateFile",  action="store")
parser.add_argument("--caCertificate", help="certification authority certificate location, PEM file", dest="caCertificateFile",  action="store")
results = parser.parse_args()

caCertificate = M2Crypto.X509.load_cert(results.caCertificateFile)
selfCertificate = M2Crypto.X509.load_cert(results.selfCertificateFile)
privateKey = M2Crypto.RSA.load_key(results.privateKeyFile)

#alterar depois o caminho!!
activeUsers = ActiveUsers("./commandsLog.xml")

#
inQueue = Queue.Queue()
communicationManager = CommunicationManager(inQueue)

print "we are online"

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(('google.com', 0))
serverIP = s.getsockname()[0]

#1 thread in the begining
clientProxy = ClientProxy(inQueue, "/etc/cc/authorizedUsers.xml", activeUsers, privateKey, selfCertificate, caCertificate, serverIP)
clientProxy.start()

clientProxy2 = ClientProxy(inQueue, "/etc/cc/authorizedUsers.xml", activeUsers, privateKey, selfCertificate, caCertificate, serverIP)
clientProxy2.start()

sessionVerifierThread = SessionVerifierThread(activeUsers, Constants.TIMEOUT) #eache 60secunds
sessionVerifierThread.start()

#criar thread de verificacao