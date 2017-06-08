#!/usr/bin/python3
"""
customer ldap server written to log bug 
https://issues.alfresco.com/jira/browse/MNT-17966

author: Alex Madon
"""
# https://docs.python.org/3/library/socket.html
# ldapsearch -x -H ldap://localhost:3389 -D "cn=Administrator,cn=Users,dc=example,dc=foo" -w mypass -b 'dc=example,dc=foo' '(objectclass=*)'
# ldapsearch -x -H ldap://localhost:3389 -D "cn=Administrator,cn=Users,dc=example,dc=foo" -w mypass -b 'dc=example,dc=foo' '(&(objectclass=groupOfNames)(!(modifyTimestamp<=20150302092004Z)))'
# ldapsearch -x -H ldap://localhost:3389 -D "cn=Administrator,cn=Users,dc=example,dc=foo" -w mypass -b 'dc=example,dc=foo' '(objectclass=groupOfNames)'


# ldapsearch -x -H ldap://localhost:3389 -D "cn=Administrator,cn=Users,dc=example,dc=foo" -w mypass -b 'dc=example,dc=foo' '(objectclass=groupOfNames)' cn description member modifyTimestamp

# ldapsearch -x -H ldap://localhost:3389 -D "cn=Administrator,cn=Users,dc=example,dc=foo" -w mypass -s base -b 'cn=foouser11,cn=Users,dc=example,dc=foo' '(objectclass=*)' objectclass cn uid



# https://tools.ietf.org/html/rfc4511
# https://github.com/richm/scripts/blob/master/decode-ldap-ber.py
# root@madona:~# apt-get install python3-pyasn1 python3-pyasn1-modules 


# https://pypi.python.org/pypi/pyasn1/0.0.12a
# madon@madona:~/tmp$ find -name ldap.py
# ./pyasn1-0.0.12a/examples/ldap.py

# http://ldap3.readthedocs.io/bind.html
# https://github.com/CoreSecurity/impacket/blob/master/impacket/ldap/ldapasn1.py
# https://cwiki.apache.org/confluence/display/DIRxSRVx10/Ldap+ASN.1+Codec
# https://github.com/CoreSecurity/impacket/issues/264
# https://github.com/CoreSecurity/impacket/blob/master/impacket/ldap/ldapasn1.py
# https://github.com/ironport/shrapnel/blob/master/old/ldap/ldap.py
# https://github.com/cannatag/ldap3
#     ./ldap3/operation/bind.py
# https://github.com/CoreSecurity/impacket/blob/master/impacket/ldap/ldapasn1.py

"""

ldapsearch -x -H ldap://localhost:3389 -D "cn=Administrator,cn=Users,dc=example,dc=foo" -w mypass -b 'dc=example,dc=foo' '(objectclass=*)'




alfresco 5.1.1



authentication.chain=ldap:ldap
ldap.authentication.java.naming.provider.url=ldap://localhost:389
ldap.authentication.userNameFormat=cn=%s,cn=Users,dc=example,dc=foo
ldap.authentication.java.naming.security.authentication=simple
ldap.authentication.active=true
ldap.authentication.defaultAdministratorUserNames=administrator

# LDAP sync openldap
ldap.synchronization.active=true
ldap.synchronization.java.naming.security.principal=CN=Administrator,CN=Users,DC=example,DC=foo
ldap.synchronization.java.naming.security.credentials=mypass
ldap.synchronization.userSearchBase=cn=Users,DC=example,DC=foo
ldap.synchronization.groupSearchBase=ou=groups,DC=example,DC=foo


the rest is default:

$type                                                      ldap
** Object Name                                             Alfresco:Type=Configuration,Category=Authentication,id1=managed,id2=ldap
** Object Type                                             Authentication$managed$ldap
instancePath                                               [managed, ldap]
ldap.authentication.active                                 true
ldap.authentication.allowGuestLogin                        true
ldap.authentication.authenticateFTP                        true
ldap.authentication.defaultAdministratorUserNames          administrator
ldap.authentication.escapeCommasInBind                     false
ldap.authentication.escapeCommasInUid                      false
ldap.authentication.java.naming.factory.initial            com.sun.jndi.ldap.LdapCtxFactory
ldap.authentication.java.naming.provider.url               ldap://localhost:389
ldap.authentication.java.naming.read.timeout               0
ldap.authentication.java.naming.security.authentication    simple
ldap.authentication.userNameFormat                         cn=%s,cn=Users,dc=example,dc=foo
ldap.pooling.com.sun.jndi.ldap.connect.pool.authentication none simple
ldap.pooling.com.sun.jndi.ldap.connect.pool.debug          
ldap.pooling.com.sun.jndi.ldap.connect.pool.initsize       1
ldap.pooling.com.sun.jndi.ldap.connect.pool.maxsize        
ldap.pooling.com.sun.jndi.ldap.connect.pool.prefsize       
ldap.pooling.com.sun.jndi.ldap.connect.pool.protocol       plain
ldap.pooling.com.sun.jndi.ldap.connect.pool.timeout        
ldap.pooling.com.sun.jndi.ldap.connect.timeout             
ldap.synchronization.active                                true
ldap.synchronization.attributeBatchSize                    0
ldap.synchronization.com.sun.jndi.ldap.connect.pool        true
ldap.synchronization.defaultHomeFolderProvider             largeHomeFolderProvider
ldap.synchronization.enableProgressEstimation              true
ldap.synchronization.groupDifferentialQuery                (&(objectclass=groupOfNames)(!(modifyTimestamp<={0})))
ldap.synchronization.groupDisplayNameAttributeName         description
ldap.synchronization.groupIdAttributeName                  cn
ldap.synchronization.groupMemberAttributeName              member
ldap.synchronization.groupQuery                            (objectclass=groupOfNames)
ldap.synchronization.groupSearchBase                       ou=groups,DC=example,DC=foo
ldap.synchronization.groupType                             groupOfNames
ldap.synchronization.java.naming.security.authentication   simple
ldap.synchronization.java.naming.security.credentials      mypass
ldap.synchronization.java.naming.security.principal        CN=Administrator,CN=Users,DC=example,DC=foo
ldap.synchronization.modifyTimestampAttributeName          modifyTimestamp
ldap.synchronization.personDifferentialQuery               (&(objectclass=inetOrgPerson)(!(modifyTimestamp<={0})))
ldap.synchronization.personQuery                           (objectclass=inetOrgPerson)
ldap.synchronization.personType                            inetOrgPerson
ldap.synchronization.queryBatchSize                        0
ldap.synchronization.timestampFormat                       yyyyMMddHHmmss'Z'
ldap.synchronization.userEmailAttributeName                mail
ldap.synchronization.userFirstNameAttributeName            givenName
ldap.synchronization.userIdAttributeName                   uid
ldap.synchronization.userLastNameAttributeName             sn
ldap.synchronization.userOrganizationalIdAttributeName     o
ldap.synchronization.userSearchBase                        cn=Users,DC=example,DC=foo




** Object Name                             Alfresco:Type=Configuration,Category=Synchronization,id1=default
** Object Type                             Synchronization$default
synchronization.allowDeletions             true
synchronization.autoCreatePeopleOnLogin    true
synchronization.import.cron                0 0 0 * * ?
synchronization.loggingInterval            100
synchronization.syncDelete                 true
synchronization.syncOnStartup              true
synchronization.syncWhenMissingPeopleLogIn true
synchronization.synchronizeChangesOnly     true
synchronization.workerThreads              1


"""
import socket
import _thread
import time
import sys, getopt

from pyasn1.type import univ

import ldapasn1 as ldap

def log(*args):
        print('DEBUG ', end='')
        print(*args)
        
def searchresultdone():

        # SearchResultDone
        xx='searchresultdone'
        msg=ldap.SearchResultDone()
        msg['resultCode']=0
        msg['matchedDN']=''
        msg['diagnosticMessage']=''
        
        log(xx,msg.prettyPrint())
        return msg

def searchresultentry_group(atts):
        xx="searchresultentry_group"

        # log(xx,"WAITING")
        # time.sleep(7)
        msg=ldap.SearchResultEntry()
        msg['objectName']='cn=foogroup10,ou=groups,dc=example,dc=foo'
        
        
        att1=ldap.PartialAttribute()
        att1['type']='cn'
        att1['vals']=None
        att1['vals'].setComponentByPosition(0, 'foogroup10')


        att2=ldap.PartialAttribute()
        att2['type']='description'
        att2['vals']=None
        att2['vals'].setComponentByPosition(0, 'group foogroup10')

        att3=ldap.PartialAttribute()
        att3['type']='member'
        att3['vals']=None
        att3['vals'].setComponentByPosition(0, 'cn=foouser10,cn=Users,dc=example,dc=foo')
        att3['vals'].setComponentByPosition(1, 'cn=foouser11,cn=Users,dc=example,dc=foo')


        att4=ldap.PartialAttribute()
        att4['type']='modifyTimestamp'
        att4['vals']=None
        att4['vals'].setComponentByPosition(0, '20150302092004Z')

        
        # att1['vals'].setComponentByPosition(1, 'admins')
        # log(xx,'PartialAttribute',att1.prettyPrint())


        
        msg['attributes']=ldap.PartialAttributeList()
        msg['attributes'].setComponentByPosition(0, att1)
        msg['attributes'].setComponentByPosition(1, att2)
        msg['attributes'].setComponentByPosition(2, att3)
        msg['attributes'].setComponentByPosition(3, att4)


        return msg
        
def searchresultentry_user(baseobs,atts):
        # SearchResultEntry
        xx='searchresultentry_user'



        log(xx,"WAITING")
        time.sleep(time2wait)

        msg=ldap.SearchResultEntry()
        


        msg['objectName']=baseobs
        usernames={}
        usernames['cn=foouser11,cn=Users,dc=example,dc=foo']='foouser11'
        usernames['cn=foouser10,cn=Users,dc=example,dc=foo']='foouser10'
        username=usernames[baseobs]
        
        att1=ldap.PartialAttribute()
        att1['type']='cn'
        att1['vals']=None
        att1['vals'].setComponentByPosition(0, username)


        att2=ldap.PartialAttribute()
        att2['type']='uid'
        att2['vals']=None
        att2['vals'].setComponentByPosition(0, username)

        att3=ldap.PartialAttribute()
        att3['type']='objectclass'
        att3['vals']=None
        att3['vals'].setComponentByPosition(0, 'inetOrgPerson')
        att3['vals'].setComponentByPosition(1, 'organizationalPerson')
        att3['vals'].setComponentByPosition(2, 'person')
        att3['vals'].setComponentByPosition(3, 'top')

        
        msg['attributes']=ldap.PartialAttributeList()
        msg['attributes'].setComponentByPosition(0, att1)
        msg['attributes'].setComponentByPosition(1, att2)
        msg['attributes'].setComponentByPosition(2, att3)
        

        return msg
        
def searchresultentry_allusers(baseobs,atts):

        msgs=[]
        users=[
                ('foouser10','cn=foouser10,cn=Users,dc=example,dc=foo'),
                ('foouser11','cn=foouser11,cn=Users,dc=example,dc=foo'),
                ('administrator','cn=Administrator,cn=Users,dc=example,dc=foo'),
       ]

        for (username,dn) in users:

                msg=ldap.SearchResultEntry()
        


                msg['objectName']=username
                
                att1=ldap.PartialAttribute()
                att1['type']='uid'
                att1['vals']=None
                att1['vals'].setComponentByPosition(0, username)
                
                """
                att2=ldap.PartialAttribute()
                att2['type']='uid'
                att2['vals']=None
                att2['vals'].setComponentByPosition(0, username)
                
                att3=ldap.PartialAttribute()
                att3['type']='objectclass'
                att3['vals']=None
                att3['vals'].setComponentByPosition(0, 'inetOrgPerson')
                att3['vals'].setComponentByPosition(1, 'organizationalPerson')
                att3['vals'].setComponentByPosition(2, 'person')
                att3['vals'].setComponentByPosition(3, 'top')
                """
                
                msg['attributes']=ldap.PartialAttributeList()
                msg['attributes'].setComponentByPosition(0, att1)
                """
                msg['attributes'].setComponentByPosition(1, att2)
                msg['attributes'].setComponentByPosition(2, att3)
                """
                msgs.append(msg)
                
                

        return msgs
                
def bindresponse(op):
        # bindResponse
        xx='bindresponse'
        name=op['bindRequest']['name']
        sname=str(name)
        sname=sname.lower()
        
        log(xx,'name',name)
        log(xx,'sname',sname)
        simple=op['bindRequest']['authentication']['simple']
        simple=str(simple)
        log(xx,'simple',simple)

        
        xx='bindresponse'
        msg=ldap.BindResponse()
        if sname=='cn=administrator,cn=users,dc=example,dc=foo' and simple=='mypass':
                msg['resultCode']=0
                msg['matchedDN']='cn=Administrator,cn=Users,dc=example,dc=foo'
                msg['diagnosticMessage']='success'
                
        else:
                
                msg['resultCode']='invalidCredentials'
                msg['matchedDN']=''
                msg['diagnosticMessage']=''
                
        
        log(xx,'pos0(name)',msg.getNameByPosition(0))
        log(xx,'pos0(component)',msg.getComponentByPosition(0))
        log(xx,'pos1(name)',msg.getNameByPosition(1))
        log(xx,'pos1(component)',msg.getComponentByPosition(1))
        log(xx,'pos2(name)',msg.getNameByPosition(2))
        log(xx,'pos2(component)',msg.getComponentByPosition(2))
        log(xx,'pos3(name)',msg.getNameByPosition(3))
        
        
        log(xx,'BindResponse',msg.prettyPrint())
        
        
        return msg



def searchresultentries(op):
        xx='searchresultentries'
        entries=[]
        # need more analysis on op:
        log(xx,op.prettyPrint())
        baseObject=op['searchRequest']['baseObject']
        baseobs=str(baseObject)
        log(xx,'baseObject',baseObject)
        attributes=op['searchRequest']['attributes']
        # log(xx,'attributes',attributes)
        # log(xx,'dir_attributes',dir(attributes))
        # log(xx,'attributes._componentValues',attributes._componentValues)
        # log(xx,'attributes._componentValuesSet',attributes._componentValuesSet)
        atts=[]
        for attribute in attributes:
                log(xx,'attribute',attribute)
                atts.append(str(attribute))
        log(xx,'atts',atts)
        assertionValue=str(op['searchRequest']['filter']['equalityMatch']['assertionValue'])

        log(xx,'assertionValue',assertionValue)
        if assertionValue=='groupOfNames':
                log(xx,'processing Group request')
                entries.append(searchresultentry_group(atts))
        else:
                log(xx,'not a group request')
                if baseobs in ['cn=foouser10,cn=Users,dc=example,dc=foo','cn=foouser11,cn=Users,dc=example,dc=foo']:
                        log(xx,'baseObject is one of the known users')
                        entries.append(searchresultentry_user(baseobs,atts))
                else:
                        log(xx,'not a single user request')
                        if baseobs in ['cn=Users,DC=example,DC=foo']:
                                log(xx,'baseObject is the user base')
                                entries=entries+searchresultentry_allusers(baseobs,atts)


                
        # dispatcher
        # if 
        return entries

def dispatch(ldapMessage):
        # get the message ID
        xx='dispatch'
        messageid=ldapMessage['messageID']
        log(xx,'messageID=',messageid)


        op=ldapMessage['protocolOp']
        name=op.getName()
        log(xx,'opname',name)

        msgs=[]
        if name=='bindRequest':
                msgs.append(bindresponse(op))
        elif name=='searchRequest':
                entries=searchresultentries(op)
                msgs=msgs+entries
                msgs.append(searchresultdone())
        elif name=='unbindRequest':
                log(xx,'unbindRequest, doing nothing')
                
        elif name=='abandonRequest':
                log(xx,'abandonRequest, doing nothing')
        else:
                log(xx,"DID NOT FIND TYPE",name)
        return (msgs,messageid)




def process_request(request):
        xx='process_request'
        log(xx)
        log(xx)
        log(xx)
        log(xx,'>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>')
        log(xx,'=====> Got request')
        log(xx,request)
        ldapMessage, _ = ldap.decoder.decode(request, asn1Spec=ldap.LDAPMessage())
        log(xx,ldapMessage.prettyPrint())


        
        log(xx)
        log(xx)
        log(xx)
        log(xx,'<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<')
        # a dispatcher
        (response_ops,messageid)=dispatch(ldapMessage)

        ldapResponses=[]

        if response_ops:
                for response_op in response_ops:
                        # create a full ldap message:
                        ldapResponse = ldap.LDAPMessage()
                        ldapResponse['messageID'] = messageid
                        log(xx,'setting protocolOp in ldap response')
                        # see ./impacket-master/impacket/ldap/ldap.py:
                        # message['protocolOp'].setComponentByType(request.getTagSet(), request)
                        ldapResponse['protocolOp'].setComponentByType(response_op.getTagSet(), response_op)
                        log(xx,'<== Sending Response')
                        log(xx,'LDAP Response',ldapResponse.prettyPrint())
                        ldapResponses.append(ldapResponse)
                return ldapResponses
        else:
                return None
    
def send_response(response,client):
        xx='send_response'
        bytes2send=ldap.encoder.encode(response)
        log(xx,'bytes2send',bytes2send)
        sent = client.sendall(bytes2send)
        log(xx,'sent',sent)



def read_request(client):
        xx='read_request'
        request = client.recv(255)
        if request != "":                
                response=process_request(request)
                if response:
                        send_response(response,client)
                        read_request(client)
                else:
                        log(xx,"Closing client connection")
                        client.close()
                        # s.close()  



     

def handler(client,address):
        xx='handler'
        keep=True
        while keep:
                request = client.recv(255)
                if request:
                        responses=process_request(request)
                        if responses:
                                for response in responses:
                                        send_response(response,client)
                else:
                        log(xx,"Closing client connection from",address)
                        client.close()
                        keep=False


                        
        # client.close()
        # log(xx,address, "- closed connection")
 
def serve():
        xx='serve'
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ldap_server_port=3389
        log(xx,"Binding ldap server to port",ldap_server_port)
        s.bind(('', ldap_server_port))
        s.listen(5)

        while True:
                # s.listen(5)
                log(xx,"Waiting for incoming connections on port",ldap_server_port)
                client, address = s.accept()
                log(xx,"Client {} connected".format( address ))
                # read_request(client)
                _thread.start_new_thread(handler, (client, address))

        log(xx,"Close")
        client.close()
        s.close()
                



if __name__ == "__main__":
        time2wait=0
        optlist, list = getopt.getopt(sys.argv[1:], 's:')
        for option in optlist:
                if option[0] == '-s':
                        time2wait=int(option[1])
                        log('main',"time2wait",time2wait)
                        log('main',"should be greater than ldap.authentication.java.naming.read.timeout")
                
        serve()
        
