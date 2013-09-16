from database import Base, db_session
from sqlalchemy import Column, Integer, TEXT, String, BigInteger
#from sqlalchemy.dialects.postgresql import TEXT
from sqlalchemy.sql import and_

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
    owner   = Column(String(256))
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
            'owner': self.owner,
            'catalog':self.catalog,
            'query':self.query,
            'code':self.code,
            'token':self.token,
            'status':self.status
        }
        
    def __repr__(self):
        return "{state:'%s', resource:'%s', resource_uri:'%s', expiry: %d, redirect:'%s', owner:'%s', catalog:'%s', query:'%s', code:'%s', token:'%s', status:'%s'}" % (self.state, self.resource, self.resource_uri, self.expiry, self.redirect, self.owner, self.catalog, self.query, self.code, self.token, self.status)

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
    return db_session.query(ExecutionRequest).filter(ExecutionRequest.execution_id==execution_id).first()


def addExecutionResponse(execution_id, access_token, result, received):
    response = ExecutionResponse(execution_id = execution_id, access_token=access_token, result=result, received=received)
    
    try:
        db_session.add(response)
        db_session.commit()   
    except:
        db_session.rollback()
        raise
        return False
    
    return True
    

def getExecutionResponse(execution_id, access_token):
    return db_session.query(ExecutionResponse.result, ExecutionResponse.execution_id).filter(and_(ExecutionResponse.execution_id==execution_id, ExecutionResponse.access_token==access_token)).first()

def getAllExecutionResponses():

    result = db_session.query(ExecutionResponse.execution_id, ExecutionResponse.received, ExecutionResponse.access_token, ExecutionRequest.parameters, ProcessorRequest.query).filter(ExecutionRequest.execution_id ==ExecutionResponse.execution_id).filter(ProcessorRequest.token == ExecutionResponse.access_token).all()
    
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
    
    
def addProcessorRequest(state, catalog, resource, resource_uri, owner, redirect, expiry, query):   
    prorec = ProcessorRequest(state=state, catalog=catalog, resource=resource, resource_uri=resource_uri, owner=owner, redirect=redirect, expiry=expiry, query=query, status="pending")
    
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
  
def getProcessorRequests():
     return db_session.query(ProcessorRequest).all()
     

    
def purgedata():
    db_session.query(ProcessorRequest).delete()
    db_session.query(Identifier).delete()
    db_session.query(ExecutionRequest).delete()
    db_session.query(ExecutionResponse).delete()
    
    try:
        db_session.commit()   
    except:
        db_session.rollback()
        raise
        return False
    
    return True   
    
