import os
import sys
from flask import Flask, Response, request, url_for, render_template, flash, redirect, session, jsonify
from util import *
import urllib2
import urllib
import urlparse
import json
import OpenIDManager
import hashlib
import ConfigParser
from database import init_db
from datetime import datetime, timedelta
from functools import wraps
from UpdateManager import *
from gevent.wsgi import WSGIServer
import ast
import random
import httplib

configfile = sys.argv[1]
Config = ConfigParser.ConfigParser()
Config.read(configfile)
ROOT_PATH = Config.get("DatawareClient", "root_path")
app = Flask(__name__, template_folder="%s/templates" % ROOT_PATH, static_folder="%s/static" % ROOT_PATH)
app.secret_key = Config.get("DatawareClient", "secret_key")
init_db(Config.get("DatawareClient",'uri'))
from models import *
um = UpdateManager()

#-----constants------------
PORT        = Config.get("DatawareClient", "port")
CATALOG     = Config.get("DatawareClient", "catalog")
REALM       = Config.get("DatawareClient", "realm")
CLIENTNAME  = Config.get("DatawareClient", "clientname") 
RESOURCEUSERNAME = Config.get("DatawareClient", "resourceusername") 
RESOURCENAME     = Config.get("DatawareClient", "resourcename") 
EXTENSION_COOKIE = Config.get("DatawareClient", "extension_cookie")
RESOURCEURI = Config.get("DatawareClient", "resource")
fileList = []

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if (session.get("logged_in") == None):
            return redirect(url_for('root'))
        return f(*args, **kwargs)
    return decorated_function
    
@app.route('/')
def root():

    return render_template('login.html')
    #session['logged_in'] = True 
    #return render_template('summary.html')

@app.route('/login')
def login():

    provider = request.args.get('provider', None)  
    params=""
    
    try:
        url = OpenIDManager.process(
            realm=REALM,
            return_to=REALM + "/checkauth?" + urllib.quote( params ),
            provider=provider
        )
    except Exception, e:
        app.logger.error( e )
        return user_error( e )
    
    #Here we do a javascript redirect. A 302 redirect won't work
    #if the calling page is within a frame (due to the requirements
    #of some openid providers who forbid frame embedding), and the 
    #template engine does some odd url encoding that causes problems.
    app.logger.info("calling url %s" % url)
    
    return "<script>self.parent.location = '%s'</script>" % url

@app.route( "/checkauth")
def user_openid_authenticate():
    
    #o = OpenIDManager.Response( request.GET )
    o = OpenIDManager.Response(request.args)
  
  
    #check to see if the user logged in succesfully
    if ( o.is_success() ):
        
        user_id = o.get_user_id()
        email = o.get_user_email()
       
        #if so check we received a viable claimed_id
        if user_id:
            try:
                
               
                session['logged_in'] = True 
                #user = db.user_fetch_by_id( user_id )
                 
                #if this is a new user add them
                #if ( not user ):
                #    db.user_insert( o.get_user_id() )
                #    user_name = None
                #else :
                #    user_name = user.user_name
                
                #_set_authentication_cookie( user_id, user_name  )
                
            except Exception, e:
                return user_error( e )
            
            
        #if they don't something has gone horribly wrong, so mop up
        else:
            _delete_authentication_cookie()

    #else make sure the user is still logged out
    else:
        _delete_authentication_cookie()
        
    try:
        # redirect_uri = "resource_request?resource_id=%s&redirect_uri=%s&state=%s" % \
        #     ( request.GET[ "resource_id" ], 
        #       request.GET[ "redirect_uri" ], 
        #       request.GET[ "state" ] )
        redirect_uri = "resources" 
    except:
        redirect_uri = REALM + ROOT_PAGE
    
    return "<script>self.parent.location = '%s'</script>" % ( redirect_uri, )
   
@app.route('/resources')
@login_required
def resources():
    
    return render_template('resources.html', catalogs=["%s" % CATALOG], processors=getProcessorRequests(),resource_uri=RESOURCEURI);
    
    
@app.route('/request_resources')
@login_required
def request_resources():
    catalog  =  request.args.get('catalog_uri', None)  
    client = fetchIdentifier(catalog)
    url = "%s/client_list_resources?client_id=%s&client_uri=%s" % (catalog, client.id, client.redirect) 
    f = urllib2.urlopen(url)
    data = f.read()  
    f.close()
    return data

@app.route('/schema', methods=['POST'])
def schema():
    resource_uri = request.form['resource_uri']
    resource_name = request.form['resource_name']
    parsed = urlparse.urlparse(resource_uri)
    path   = "schema" if parsed.path[1:] == "" else "%s/schema" % parsed.path
    scheme = "http" if parsed.scheme[1:] == "" else "%s" % parsed.scheme 
    url = "%s://%s.%s/%s" % (scheme, resource_name, parsed.netloc, path) 
    f = urllib2.urlopen(url)
    data = f.read()  
    f.close()
    return data
        
@app.route('/register', methods=['GET','POST'])
@login_required
def register():

    if request.method == 'POST':
        catalog = request.form['catalog_uri']
        
        if not fetchIdentifier(catalog) is None:
            flash('Already registered with %s' % catalog)
            return redirect(url_for('resources'))
        
        url = "%s/client_register" % catalog
        
        values = {
                'redirect_uri': "%s/%s" % (REALM, "processor"),
                'client_name':CLIENTNAME
             }
    
        data = urllib.urlencode(values)
        req = urllib2.Request(url,data)
        response = urllib2.urlopen(req)
        result = response.read()
        result = json.loads( 
                    result.replace( '\r\n','\n' ), 
                    strict=False 
                )
                
        if (result['success']):
            addIdentifier(catalog, "%s/%s" % (REALM, "processor"), result['client_id'])
        
        flash('Successfully registered with %s' % catalog)
        return redirect(url_for('resources'))
    
    else:
    
        return render_template('register.html', catalogs=["%s" % CATALOG])
        

@app.route('/request', methods=['GET','POST'])
@login_required
def request_processor():
    
    error = None
    
    if request.method == 'POST':
       
        expiry = request.form['expiry']
        catalog = request.form['catalog'] 
        query = request.form['query'].replace('\n',  ' ')
        resource_name = request.form['resource_name']
        resource_uri = request.form['resource_uri']
        owner = request.form['owner']
        state = generateuniquestate()
        client = fetchIdentifier(catalog)
    
        values = {
            'client_id': client.id,
            'state': state,
            'redirect_uri': client.redirect,
            'scope': '{"resource_name" : "%s", "expiry_time": %s, "query": "%s"}' % (resource_name,expiry,query)
        }
        
       
        app.logger.info(values)
       
        url = "%s/user/%s/client_request" % (catalog,owner)
        
        app.logger.info(url)
        
        data = urllib.urlencode(values)
        req = urllib2.Request(url,data)
        response = urllib2.urlopen(req)
        result = response.read()
        result = json.loads( 
                result.replace( '\r\n','\n' ), 
                strict=False 
            )
            
        app.logger.info(result)    
        
        if (not(result['success'])):
            return json.dumps({'success':False})
        
        #store the state and the code and the various bits for re-use?
         
        addProcessorRequest(state=state, catalog=catalog, resource=resource_name,resource_uri=resource_uri,redirect=client.redirect,expiry=int(expiry),query=query)
        
        return json.dumps({'success':True, 'state':state})
    
    else:
        #provide the user with the options relating to our catalogs
        options = {
            'catalogs': [CATALOG],
            'resources': [RESOURCENAME],
            'owners': [RESOURCEUSERNAME]
        }
        return render_template('request.html', options=options, error=error)

#/////////////////////////////////////////////////////////////////////
#For Experiment request made by client
@app.route('/experimentRequest', methods=['GET','POST'])
@login_required
def request_experiment_processor():
    
    error = None
    
    if request.method == 'POST':
        
        expiry = request.form['expiry']
        catalog = request.form['catalog'] 
        query = request.form['query']
        resource_name = request.form['resource_name']
        resource_uri = request.form['resource_uri']
        owner = request.form['owner']
        state = generateuniquestate()
        client_id = fetchClient(catalog);
        redirect_uri = REALM + '/processor'
        
        #Check if this client is registered with the catalog if not then register it
        
        
        print("Inside experiment Request client % s "  % redirect_uri)    
        values = {
            'client_id': client_id,
            'state': state,
            'redirect_uri': redirect_uri,
            'scope': '{"resource_name" : "%s", "expiry_time": %s, "query": "%s"}' % (resource_name,expiry,query)
        }
        
       
        app.logger.info(values)
        
        url = "%s/user/%s/client_request" % (catalog,owner)
        
        app.logger.info(url)
        
        data = urllib.urlencode(values)
        req = urllib2.Request(url,data)
        response = urllib2.urlopen(req)
        result = response.read()
        result = json.loads( 
                result.replace( '\r\n','\n' ), 
                strict=False 
            )
              
        app.logger.info(result)    
        
        if (not(result['success'])):
            return json.dumps({'success':False})
        
        #store the state and the code and the various bits for re-use?
           
        addProcessorRequest(state=state, catalog=catalog, resource=resource_name,resource_uri=resource_uri,redirect=redirect_uri,expiry=int(expiry),query=query)
        
        
        #after successful processor request installation redirect to catalog screen to accept the request
        data = urllib.urlencode({
            'fromPage': 'expClient',           
            'redirect': REALM + '/resources', }) 
        redirect_url = "%s/audit?%s" % ( catalog, data ) 
        return json.dumps({'success':True, 'redirect':redirect_url})
    
    else:
        #provide the user with the options relating to our catalogs
        options = {
            'catalogs': [CATALOG],
            'resources': [RESOURCENAME],
            'owners': [RESOURCEUSERNAME]
        }
        return render_template('request.html', options=options, error=error)





def fetchClient(catalog):
    if not fetchIdentifier(catalog) is None:
            print('Already registered with %s' % catalog)
            return fetchIdentifier(catalog).id
        
    url = "%s/client_register" % catalog
        
    values = {
            'redirect_uri': "%s/%s" % (REALM, "processor"),
            'client_name':CLIENTNAME
         }

    data = urllib.urlencode(values)
    req = urllib2.Request(url,data)
    response = urllib2.urlopen(req)
    result = response.read()
    result = json.loads( 
                result.replace( '\r\n','\n' ), 
                strict=False 
            )
            
    if (result['success']):
        addIdentifier(catalog, "%s/%s" % (REALM, "processor"), result['client_id'])
        return result['client_id']
    
    print('Successfully registered with %s' % catalog)
    return None
    





def createExecutionReq(state,parameters):
    if state is not None:
        print "inside createExecutionReq *****"
        #parameters = None 
        processor = getProcessorRequest(state=state)
        if not(processor is None):
            print "inside processor and url is % s *****" % processor.resource_uri 
            url = '%s/invoke_processor' % processor.resource_uri
            
            m = hashlib.md5()
            m.update('%f' % time.time())
            id = m.hexdigest()  
            values = {
                'access_token':processor.token,
                'parameters': parameters,
                'result_url' : "%s/result/%s" % (REALM,id),
                'view_url' : "%s/view/%s" % (REALM,id)
            }

            data = urllib.urlencode(values)
            req = urllib2.Request(url,data)
            print "before response *****"  
            response = urllib2.urlopen(req)
            print "after response *****"  
            data = response.read()
            response.close()
            result = json.loads(data.replace( '\r\n','\n' ), strict=False)
            print "*********** result is %s " % result
            addExecutionRequest(execution_id=id, access_token=processor.token, parameters=parameters, sent=int(time.time()))
            print "******* s" 
            
    else:
        processors = getProcessorRequests()
        return render_template('execute.html', processors=processors)




@app.route('/processor')
def token():

    app.logger.info(request.args)
    
    error = request.args.get('error', None)
    state =  request.args.get('state', None)
    
    if not(error is None):
        app.logger.info(error)
        app.logger.info(request.args.get('error_description', None))
        prec = updateProcessorRequest(state=state, status=error)
        
        um.trigger({    
                "type": "resource",
                "message": "a resource request has been rejected",
                "data": json.dumps(prec.serialize)                   
        });
        
        return "Noted rejection <a href='%s/audit'>return to catalog</a>" % prec.catalog
    
    code  =  request.args.get('code', None)
   
    prec = updateProcessorRequest(state=state, status="accepted", code=code)
    
    #if successful, swap the auth code for the token proper with catalog
    if not(prec is None): 
        url = '%s/client_access?grant_type=authorization_code&redirect_uri=%s&code=%s' % (prec.catalog, prec.redirect,code)
        
        f = urllib2.urlopen(url)
        
        data = f.read()
        
        #f.close()
        
        result = json.loads(data.replace( '\r\n','\n' ), strict=False)
        
        if result["success"]:
            prec = updateProcessorRequest(state=state, status="accepted", token=result["access_token"])    
            
            #update the client to notify of acceptance.
            
            um.trigger({    
                "type": "resource",
                "message": "a resource request has been accepted",
                "data": json.dumps(prec.serialize)                   
            });
            parameters = '{}'
            print "before create execution req*****"
            createExecutionReq(state=state,parameters=parameters) 
            redirect_uri = "resources" 
            return "<script>self.parent.location = '%s'</script>" % ( redirect_uri)                             
        else:
            
            return  "Failed to swap auth code for token <a href='%s/audit'>return to catalog</a>" % prec.catalog
            
    return "No pending request found for state %s" % state
 

@app.route('/startExp')
@login_required
def startExp():
    print "Inside startEXP ****************"
    return  render_template('startExp.html')


@app.route('/processors')
@login_required
def processors():
    try:
        processors =  getProcessorRequests()
    except:
        e,p,t = sys.exc_info()
        print e,p
    return jsonify(processors=[p.serialize for p in processors])  
   
   
    
@app.route('/purge')
@login_required
def purge():
    purgedata()
    return redirect(url_for('root'))

@app.route('/result/<execution_id>', methods=['POST'])
def result(execution_id):
    
    success = True
    
    try:
        if (request.form['success'] == 'True'):
            execution_request = getExecutionRequest(execution_id)
            result = request.form['return']
              
            if not(execution_request is None):
                #addExecutionResponse(execution_id=execution_id, access_token=execution_request.access_token, result=str(result), received=int(time.time()))
                addExperimentResponse(execution_id=execution_id, result=str(result), received=int(time.time()))
        else:
            print "not doing anything at the mo!"
                        
    except:
        success = False
           
    return json.dumps({'success':success}) 
    
    
@app.route('/view/<execution_id>', methods=['POST'])
def view(execution_id):
    
    #should the hwresource owner have to register with the TPC?  Think it'd be a 
    #bit of an interaction headache, better that the shared id's is assumed enough
    #to authenticate a request to view a processing output.
    
    #third party client received when this registered with catalog
    #client_id = request.form['client_id'] 
    
    #processor access token
    processor_id = request.form['processor_id'] 
       
    #lookup the execution details and confirm that this user is allowed access. Return a page
    #with the same view of the data as seen by this TPC.
    
    data = getExecutionResponse(execution_id=execution_id, access_token=processor_id)
    
    values = json.loads(data.result.replace( '\r\n','\n' ), strict=False)
    print "string is ^^^^ %s" % str(data)
    #generalise this..
    if isinstance(values, list):
        if len(values) > 0:
            if isinstance(values[0], dict):
                keys = list(values[0].keys())
                return render_template('result.html', result=values, keys=keys)
    
    return str(data)
    

@app.route( '/stream')
@login_required
def stream():
    
    try:
        um.event.wait()
        message = um.latest()
        jsonmsg = json.dumps(message)
        return jsonmsg
        
    except Exception, e:  
        print "longpoll exception"
    
    return "goodbye"
    
@app.route('/testevent')
def testevent():
    um.trigger({    
                    "type": "test",
                    "message": "a new execution has been undertaken!",
                    "data": json.dumps({"a":"thing"})                       
                })
    return json.dumps({"result":"success"})

@app.route('/executions')
@login_required
def executions():
    executions = getAllExecutionResponses()
    return render_template("executions_summary.html", executions=executions)

@app.route('/experiment/<execution_id>')
@login_required
def experiment(execution_id):
    print "execution id is % s " % execution_id
    #get the data received from the resource
    data = getExperimentResponse(execution_id=execution_id)
    values = json.loads(data.result.replace( '\r\n','\n' ), strict=False)
    print "string is ^^^^ %s" % str(data)
    #generalise this..
    if isinstance(values, list):
        experimentUrlList = []
        if len(values) > 0:
            if isinstance(values[0], dict):
                #keys = list(values[0].keys())
                for item in values:
                    url =  str(item['url'])
                    #filter the url / check if this url points to a webpage and then add into the experiment url list
                    if not url.startswith('http'):
                        url = '%s%s' % ('http://', url)
                    if validateUrl(url):
                        experimentUrlList.append(url)
                print "length of list is % s " % len(experimentUrlList)
                
                try:
                    textFile = open("randomUrls.txt","r")
                    print "textfile is % s " % textFile
                    for line in textFile:
                        fileList.append(line)
                    print "length of fileList is % s " % len(fileList) 
                except:
                    print "exception while reading file %%%%%%% "
                    tb = traceback.format_exc()
                    print tb
                finally:
                    textFile.close()
                experimentUrlList.extend(fileList)
                random.shuffle(experimentUrlList)
                print "new length of list is % s " % len(experimentUrlList)
                access_token=None
                execution_request = getExecutionRequest(execution_id=execution_id)
                if execution_request is not None:
                    access_token = execution_request.access_token
                return render_template('experiment.html', experimentUrlList=experimentUrlList, access_token=access_token)
    
    return str(data)



#validate the url method
def validateUrl(url):
    good_codes = [httplib.OK, httplib.FOUND]
    resp = get_server_status_code(url)
    status = resp['status']
    print(  'status for %s is %s and frame option is %s' % (url,resp['status'],resp['frameOption']))
    if (status in good_codes) and (resp['frameOption'] == 'SAMEORIGIN'):
        return True
    else:
        return False

def get_server_status_code(url):
    try:
        result = head_url(url)
        return {'status':result[0], 'frameOption':result[3]  }
    except Exception, e:
        print e
        return {'status':None, 'frameOption':None  }

    
def head_url(url):
    """Perform HEAD, may throw socket errors"""
    
    def _head(url):
        """Returns a http response object"""
        
        host, path = urlparse.urlparse(url)[1:3]
        #If there is no proxy use this code        
        connection = httplib.HTTPConnection(host)
        connection.request("HEAD", path)
        
        # else for proxy execute this block of code
        #connection = httplib.HTTPConnection("mainproxy.nottingham.ac.uk", 8080)
        #connection.request("GET", url)
        return connection.getresponse()

    # redirection limit, default of 5
    redirect = 5

    # Perform HEAD
    resp = _head(url)

    # check for redirection
    while (resp.status >= 300) and (resp.status <= 399):
        # tick the redirect
        redirect -= 1

        if redirect == 0:
            # we hit our redirection limit, raise exception
            raise IOError, (0, "Hit redirection limit")

        # Perform HEAD
        url = resp.getheader('location')
        resp = _head(url)

    if resp.status >= 200 and resp.status <= 299:
        # horray!  We found what we were looking for.
        return (resp.status, url, resp.reason,resp.getheader('x-frame-options'))

    else:
        # Status unsure, might be, 404, 500, 401, 403, raise error
        # with actual status code.
        raise IOError, (resp.status, url, resp.reason,resp.getheader('x-frame-options'))



@app.route('/storeAnswer', methods=['POST'])
@login_required
def storeAnswer():
    user_id = None
    if request.method == 'POST':
        #get user details from authentication token
        if (session.get("user_id") is not None):
            user_id = session.get("user_id")
            print "inside post answer****** %s" % (user_id )
        results = request.form['finalResults']
        finalResultList = eval(ast.literal_eval(json.dumps(results)))
        print  "converted list % s" % finalResultList
        #initialise correct , incorrect and undefined parameters
        correct = incorrect = undefined = 0
        #remove\r\n from the urls before storing them in the database
        for element in finalResultList:
            element['url'] = element['url'].rstrip('\r\n')
            #check for the correct ,incorrect and no answer.
            if element['ans'] == '1':
                if element['url'] in fileList:
                    incorrect += 1
                else:
                    correct += 1
            elif element['ans'] == '0':
                if element['url'] in fileList:
                    correct += 1
                else:
                    incorrect += 1
            elif element['ans'] == '2':
                undefined += 1
              
        print('correct , incorrect and undefined values are %s, %s, %s ' %(correct,incorrect,undefined))            
            
        print "inside post answer % s ****** %s" % (user_id,finalResultList )
        try:
            result = True
            addExperimentResults(user_id=user_id,result=str(finalResultList),received=int(time.time()))
            print "Inside try of experiment results "
        except:
            print "Inside except of experiment results "
            result = False           
       
        if (result == False):
            return  render_template('experimentEnd.html')
        print "experiment over %%%"
        arrayToPass = {'correct':correct, 'incorrect':incorrect, 'undefined':undefined }
         
        return render_template('experimentEnd.html',arrayToPass=arrayToPass )
    
    else:
        #provide the user with the options relating to our catalogs
        print "inside else of store ***************"
        
        return render_template('resources.html', catalogs=["%s" % CATALOG], processors=getProcessorRequests());


@app.route('/experimentEnd', methods=['POST'])
@login_required   
def endPage():
    return render_template('experimentEnd.html');

@app.route('/logout', methods=['GET','POST'])
@login_required   
def logout():
    access_token = request.form['access_token']
    print "inside logout ***** % s" % access_token
    if access_token is not None:
        processor = getProcessorRequestByToken(access_token)  
           
        try:
            url = '%s/client_revoke/' % (CATALOG)
            data = urllib.urlencode({'auth_code':processor.code})
            req = urllib2.Request(url,data)           
            f = urllib2.urlopen(req)
            response = f.read()
            result = json.loads( 
                        response.replace( '\r\n','\n' ), 
                        strict=False 
                    )
            if (result['success']):
                deleteProcessorRequest(access_token)
                request.delete_cookie( key=EXTENSION_COOKIE)
                return render_template('login.html')
        except:
            print "error has occurred" 
            
    return render_template('experimentEnd.html');

    
@app.route('/execute', methods=['GET','POST'])
@login_required
def execute():
    if request.method == 'POST':
        access_token = request.form['access_token']
        print "inside execute ***** % s" % access_token
        executionRequest = getExecutionRequestByToken(access_token=access_token)
        return redirect(url_for('experiment', execution_id=executionRequest.execution_id ))
        #return redirect(url_for('executions'))
    else:
        processors = getProcessorRequests()
        return render_template('execute.html', processors=processors)
    
@app.route('/displayResults')
def displayResults():
    data = getAllExperimentResults()
    for row in data:
        row.result = eval(row.result) 
        print (type(row.result))
        
    #generalise this..
    return render_template('displayResults.html', results=data)

@app.route('/reset')
@login_required
def reset():
    resetdata()
    #reset data in catalog
    url = "%s/reset" % (CATALOG)
    req = urllib2.Request(url)
    response = urllib2.urlopen(req)
    output = response.read()
    print "and output is %s " % output
    #reset data in resource
    url1 = "%s/reset" % (RESOURCEURI)
    req1 = urllib2.Request(url1)
    response1 = urllib2.urlopen(req1)
    output1 = response1.read()
    print "and output for resource is %s " % output1
    return redirect(url_for('resources'))
        
def _delete_authentication_cookie():
    
    response.delete_cookie( 
        key=EXTENSION_COOKIE,
    )
        
        
def user_error( e ):
    
    return  "An error has occurred: %s" % ( e )
            
            
               
def main():
    http_server = WSGIServer(('', int(PORT)), app)
    http_server.serve_forever()
            
if __name__ == '__main__':
    main() 
 
