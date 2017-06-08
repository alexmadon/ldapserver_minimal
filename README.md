# ldapserver_minimal

This is a minimal ldap server aimed at reproducing issues in client code.

This was used to log the Alfresco LDAP sync bug at:

https://issues.alfresco.com/jira/browse/MNT-17966

It is a ldap server that can respond to few ldap requests (bind, search requests).
It is very easy to place delays:
the bug mentionned above depends on a timeout recived after a given number of ldap search requests.
With this code it is very easy to tell where to put a delay.

The -s option sets the delay to wait (see the sleep line in the server pythin code). By default there is no wait.


## Installation and use

1. install the attached minimal ldap server on a linux VM:
it consists of a main python3 script:

socketserver.py

It depends on a 2nd script:

ldapasn1.py

which is a pyasn1 implementation of the LDAP protocol and was retrieved from

https://github.com/CoreSecurity/impacket/blob/master/impacket/ldap/ldapasn1.py

socketserver.py also depends on pyasn1
http://pyasn1.sourceforge.net/

that you can install using

apt-get install python3-pyasn1

on the debian family of Linuxs or using:

pip install pyasn1

2. check that the minimal LDAP server works for the requests it has been designed to answer to:

	1. start it using:

./socketserver.py

from the folder you placed ldapasn1.py and socketserver.py

	2. check a group request with attributes:

ldapsearch -x -H ldap://localhost:3389 -D "cn=Administrator,cn=Users,dc=example,dc=foo" -w mypass -b 'dc=example,dc=foo' '(objectclass=groupOfNames)' cn description member modifyTimestamp
ldap_bind: Success (0)
	matched DN: cn=Administrator,cn=Users,dc=example,dc=foo
	additional info: success
# extended LDIF
#
# LDAPv3
# base <dc=example,dc=foo> with scope subtree
# filter: (objectclass=groupOfNames)
# requesting: cn description member modifyTimestamp 
#

# foogroup10, groups, example.foo
dn: cn=foogroup10,ou=groups,dc=example,dc=foo
cn: foogroup10
description: group foogroup10
member: cn=foouser10,cn=Users,dc=example,dc=foo
member: cn=foouser11,cn=Users,dc=example,dc=foo
modifyTimestamp: 20150302092004Z

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1

	3.check a user request:

ldapsearch -x -H ldap://localhost:3389 -D "cn=Administrator,cn=Users,dc=example,dc=foo" -w mypass -s base -b 'cn=foouser11,cn=Users,dc=example,dc=foo' '(objectclass=*)' objectclass cn uid
ldap_bind: Success (0)
	matched DN: cn=Administrator,cn=Users,dc=example,dc=foo
	additional info: success
# extended LDIF
#
# LDAPv3
# base <cn=foouser11,cn=Users,dc=example,dc=foo> with scope baseObject
# filter: (objectclass=*)
# requesting: objectclass cn uid 
#

# foouser11, Users, example.foo
dn: cn=foouser11,cn=Users,dc=example,dc=foo
cn: foouser11
uid: foouser11
objectclass: inetOrgPerson
objectclass: organizationalPerson
objectclass: person
objectclass: top

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1

3. create an alfresco 5.1.1 system (linux pg tomcat) with LDAP auth:

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

ldap.synchronization.groupDifferentialQuery=(objectclass=groupOfNames)
ldap.synchronization.groupQuery=(objectclass=groupOfNames)
ldap.synchronization.personDifferentialQuery=(objectclass=inetOrgPerson)
ldap.synchronization.personQuery=(objectclass=inetOrgPerson)

synchronization.syncDelete=true
synchronization.syncOnStartup=true
synchronization.syncWhenMissingPeopleLogIn=true
synchronization.synchronizeChangesOnly=true
synchronization.workerThreads=1


ldap.authentication.java.naming.read.timeout=5000

