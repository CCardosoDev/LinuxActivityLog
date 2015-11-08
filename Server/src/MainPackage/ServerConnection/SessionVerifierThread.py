import threading

class SessionVerifierThread(threading.Thread):
    
    def __init__ (self, activeUsers, interval):
        super(SessionVerifierThread, self).__init__()
        self.activeUsers = activeUsers
        self.interval = interval
        self.finished = threading.Event()

            
    def run(self):
        while True:
            self.activeUsers.verifyInactiveSessions()
            self.finished.wait(self.interval)      
    
    def shutdown(self):
        self.finished.set()                       
    
