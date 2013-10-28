from database import Base, db_session
from sqlalchemy import Column, Integer, String, BigInteger
from sqlalchemy.dialects.postgresql import TEXT
from sqlalchemy.sql import and_
import traceback

class Identifier(Base):
    __tablename__ = 'identifiers'
    id = Column(String(256), primary_key=True)
    redirect = Column(String(256))
    catalog  = Column(String(256))
    
    def __repr__(self):
        return "{id:'%s', redirect:'%s', catalog:'%s'}" % (self.id, self.redirect, self.catalog)

class ProcessorRequest(Base):
    __tablename__ = 'processorrequest'
    state = Column(String(256), primary_key=True)
    catalog = Column(String(256))
    resource = Column(String(256))
    resource_uri = Column(String(256))
    redirect =  Column(String(256))
    expiry = Column(BigInteger)
    query = Column(String(512))
    code = Column(String(256))
    token = Column(String(256))
    status = Column(String(256))
    
    @property
    def serialize(self):
        """ return object in easily serializable format """
        return{
            'state':self.state,
            'resource':self.resource,
            'resource_uri':self.resource_uri,
            'expiry': self.expiry,
            'redirect': self.redirect,
            'catalog':self.catalog,
            'query':self.query,
            'code':self.code,
            'token':self.token,
            'status':self.status
        }
        
    def __repr__(self):
        return "{state:'%s', resource:'%s', resource_uri:'%s', expiry: %d, redirect:'%s', catalog:'%s', query:'%s', code:'%s', token:'%s', status:'%s'}" % (self.state, self.resource, self.resource_uri, self.expiry, self.redirect, self.catalog, self.query, self.code, self.token, self.status)

class ExecutionRequest(Base):
    __tablename__ = 'executionrequest'
    execution_id = Column(String(256), primary_key=True)
    access_token = Column(String(256))
    parameters   = Column(String(256))
    sent         = Column(String(256))
    
    def __repr__(self):
        return "{execution_id:'%s', access_token:'%s', parameters:'%s', sent: %d}" % (self.execution_id, self.access_token, self.parameters, self.sent)
    
class ExecutionResponse(Base):
    __tablename__ = 'executionresponse'
    execution_id = Column(String(256), primary_key=True)
    access_token = Column(String(256))
    result = Column(TEXT)
    received = Column(Integer)
    
    def __repr__(self):
        return "{execution_id:'%s', access_token:'%s', result:'%s', received: %d}" % (self.execution_id, self.access_token, self.result, self.received)


class ExperimentResponse(Base):
    __tablename__ = 'experimentresponse'
    execution_id = Column(String(256), primary_key=True)
    result = Column(TEXT)
    received = Column(Integer)
    
    def __repr__(self):
        return "{execution_id:'%s', result:'%s', received: %d}" % (self.execution_id, self.result, self.received)
    
class ExperimentResults(Base):
    __tablename__ = 'experimentresults'
    id = Column(Integer,primary_key=True,autoincrement=True)
    user_id = Column(String(256))
    result = Column(TEXT)
    received = Column(Integer)
    
    def __repr__(self):
        return "{user_id:'%s', result:'%s',received: %d}" % (self.user_id, self.result, self.received)


def addExecutionRequest(execution_id, access_token, parameters, sent):
    request = ExecutionRequest(execution_id = execution_id, access_token=access_token, parameters=parameters, sent=sent)
    
    try:
        db_session.add(request)
        db_session.commit()   
    except:
        db_session.rollback()
        raise
        return False
    
    return True   

    
def getExecutionRequest(execution_id):
    try: 
        print "inside executionRequest execution id  is % s" % execution_id
        result = db_session.query(ExecutionRequest).filter(ExecutionRequest.execution_id==execution_id).first()
    except:
        print "inside except executionRequest"
        tb = traceback.format_exc()
        print tb
        result = None
    return result

def getExecutionRequestByToken(access_token):
    try:
        print "inside execution request"
        result = db_session.query(ExecutionRequest).filter(ExecutionRequest.access_token==access_token).first()
    except:
        tb = traceback.format_exc()
        print tb
        result = None
    return result


def addExecutionResponse(execution_id, access_token, result, received):
    response = ExecutionResponse(execution_id = execution_id, access_token=access_token, result=result, received=received)
    try:
        db_session.add(response)
        db_session.commit()   
    except:
        tb = traceback.format_exc()
        print tb
        db_session.rollback()
        raise
        return False
    
    return True

def addExperimentResponse(execution_id, result, received):
    response = ExperimentResponse(execution_id = execution_id, result=result, received=received)
    try:
        db_session.add(response)
        db_session.commit()   
    except:
        tb = traceback.format_exc()
        print tb
        db_session.rollback()
        raise
        return False
    
    return True
    

def getExecutionResponse(execution_id, access_token):
    result = db_session.query(ExecutionResponse.result, ExecutionResponse.execution_id).filter(and_(ExecutionResponse.execution_id==execution_id, ExecutionResponse.access_token==access_token)).first()
    return result

def getExperimentResponse(execution_id):
    result = db_session.query(ExperimentResponse.result, ExperimentResponse.execution_id).filter(ExperimentResponse.execution_id==execution_id).first()
    return result

def getAllExecutionResponses():

    result = db_session.query(ExecutionResponse.execution_id, ExecutionResponse.received, ExecutionResponse.access_token, ExecutionRequest.parameters, ProcessorRequest.query).filter(ExecutionRequest.execution_id ==ExecutionResponse.execution_id).filter(ProcessorRequest.token == ExecutionResponse.access_token).all()
    return result

def addExperimentResults(user_id, result, received):
    try:
        request = ExperimentResults(user_id=user_id, result=result, received=received)
        db_session.add(request)
        db_session.commit()  
    except:
        tb = traceback.format_exc()
        print tb 
        db_session.rollback()
        raise
        return False
    
    return True  

def getAllExperimentResults():

    result = db_session.query(ExperimentResults).all()
     
    return result

      
def addIdentifier(catalog, redirect, clientid):   
    identifier = Identifier(id=clientid, redirect=redirect, catalog=catalog)
    try:
        db_session.add(identifier)
        db_session.commit()   
    except:
        db_session.rollback()
        raise
        return False
    
    return True   
   
def fetchIdentifier(catalog):
    return Identifier.query.filter(Identifier.catalog==catalog).first()
    
    
def addProcessorRequest(state, catalog, resource, resource_uri, redirect, expiry, query):   
    prorec = ProcessorRequest(state=state, catalog=catalog, resource=resource, resource_uri=resource_uri, redirect=redirect, expiry=expiry, query=query, status="pending")
    try:
        db_session.add(prorec)
        db_session.commit()   
    except:
        db_session.rollback()
        raise
        return False
    
    return True   
    

def updateProcessorRequest(state, status, code=None, token=None):

    p = db_session.query(ProcessorRequest).filter(ProcessorRequest.state==state).first()

    try:
        if (not(p is None)):
            if (not(code is None)):
                p.code = code
            if (not(token is None)):
                p.token = token
                
            p.status = status
            db_session.commit() 
            return p
              
    except:
        db_session.rollback()
        raise
        
    return None

def getProcessorRequest(state): 
    return db_session.query(ProcessorRequest).filter(ProcessorRequest.state==state).first()

def getProcessorRequestByToken(token): 
    return db_session.query(ProcessorRequest).filter(ProcessorRequest.token==token).first()
  
def getProcessorRequests():
    return db_session.query(ProcessorRequest).all()
     
def purgeExperimentResponse():
    db_session.query(ExperimentResponse).delete()
    try:
        db_session.commit()   
    except:
        db_session.rollback()
        raise
        return False

def deleteProcessorRequest(access_token):
    db_session.query(ProcessorRequest).filter(ProcessorRequest.token==access_token).delete()
    try:
        db_session.commit()   
    except:
        db_session.rollback()
        raise
        return False
    return True   
    
def purgedata():
    db_session.query(ProcessorRequest).delete()
    db_session.query(Identifier).delete()
    db_session.query(ExecutionRequest).delete()
    db_session.query(ExecutionResponse).delete()
    db_session.query(ExperimentResponse).delete()
    try:
        db_session.commit()   
    except:
        db_session.rollback()
        raise
        return False
    
    return True   


def resetdata():
    db_session.query(ProcessorRequest).delete()
    db_session.query(ExecutionRequest).delete()
    db_session.query(ExecutionResponse).delete()
    db_session.query(ExperimentResponse).delete()
    try:
        db_session.commit()   
    except:
        db_session.rollback()
        raise
        return False
    
    return True   
    