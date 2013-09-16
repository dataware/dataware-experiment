import time

def generateuniquestate():
    
    state = "%d" % time.time()
    print "generated %s" % state    
    return state