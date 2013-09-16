from gevent.event import Event
  
class UpdateManager(object):
    
    def __init__(self):
        print "created update manager"
        self.event    = Event()
        print "created event object"
        self.messages = []
        print "inited message queue!"
        
    def trigger(self, message):
        try:  
            self.messages.append(message);    
            self.event.set()
            self.event.clear() 
        except Exception, e:   
            print "exception notifying" 
            print e
            
    def latest(self):
        return self.messages[-1]
        
    def queuelen(self):
        return len(self.messages)            
