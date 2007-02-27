Sign Server is a simple J2EE application that signs data 
sent to it using RMI.


See src/test/se/primeKey/signserver/ejb/TestSignSession.java for
example of how to use the API.


Requirements
---------------------------------------------

Java 1.5 http://java.sun.com
Apache-ant 1.6.2 and above http://ant.apache.org

Application Server, currently have the signserver only been tested
with JBOSS-4.0.2 http://www.jboss.org


Building and deploying
----------------------------------------------
1. Make sure that you have JBOSS_HOME and use

2. Edit the file 'signserver.properties'

3. Use 'ant' to build and 'ant deploy' to deploy it.

Testing the application using the test script
------------------------------------------------
First copy the file lib\ext\junit-3.8.1.jar to <ANT_HOME>/lib

Make sure the application server is running and the singserver 
is deployed.

Use the command 'ant test:run' to execute the testscript

Reports of the tests are generated in html format in 
tmp\bin\junit\reports\html\index.html

There also exists another testscript test:runContinously that
executes a test call every second that could be used testing
load balancing and fail-over. It's output can be seen by tailing
the file test_out.txt.

Administration using the cli GUI.
--------------------------------------------------
The sign server is administrated using a cli interface.

Every signer is identified by a id. The id is the same as 
specified in the signserver_config.properties.

It is possible to do configuration while being in production.
All configuration commands are cached until a reload command is
issued and the configuration becomes active.

The cli lies in bin\signserver.sh/cmd

Get Status Command:
Returns the status of the given signer, it says if it's signertoken is active or not
and the loaded configuration.

Get Config Command:
Returns the current configuration of signer. Observe that this config might not have been activated
yet, not untill a 'reload' command is issued.

Set Property Command
Sets a custom property used by the signer or signer token, see reference over available properties.

Remove Property Command
Removes a configured property

Upload Certificate Command
Used when updating the certificate used for signing, sign requests

Add Authorized Client Command
Adds a client certificate to a signers list of acceptable clients using this signer. specify
certificate serial number in hex and the issuerDN of the client certificate.

Removes Authorized Certificate Command
Removes added client certificates.

List Authorized Clients Commands
Displays the current list of accepable clients.

Activate Sign Token Command
Used to activate hard sign tokens, authentication code is usually the PIN used to unlock the keystore on the HSM

Deactivate Sign Token Command
Brings a Sign Token Offline.


TODO failover of the hardware specific commands (activate, deactivate, reload)


Java Documentation
--------------------------------------------------
Is generated with the command 'ant javadoc' (ignore warnings)
and outputs in the directory doc/api/index.html


MySQL Cluster
---------------------------------------------------
Here comes some notes about configuring a MySQL cluster and
perfoming the testscripts used to set it up.

Much of this HOWTO is taken from http://dev.mysql.com/tech-resources/articles/mysql-cluster-for-two-servers.html
written by Alex Davies.

A minimal cluster consists of three nodes, 2 datanodes and 
one management station.

Tested with MySQL 4.1.11 and JDBC connector 3.1.10

First install mysql ('apt-get install mysql-server' on debian)

Start with the management station:
mkdir /var/lib/mysql-cluster 
cd /var/lib/mysql-cluster 
vi [or emacs or any other editor] config.ini 

Insert the following (Without BEGIN and END):
-----BEGIN----
NDBD DEFAULT]
NoOfReplicas=2
[MYSQLD DEFAULT]
[NDB_MGMD DEFAULT]
[TCP DEFAULT]
# Managment Server
[NDB_MGMD]
HostName=192.168.0.3		# the IP of THIS SERVER
# Storage Engines
[NDBD]
HostName=192.168.0.1		# the IP of the FIRST SERVER
DataDir= /var/lib/mysql-cluster
[NDBD]
HostName=192.168.0.2		# the IP of the SECOND SERVER
DataDir=/var/lib/mysql-cluster
# 2 MySQL Clients
# I personally leave this blank to allow rapid changes of the mysql clients;
# you can enter the hostnames of the above two servers here. I suggest you dont.
[MYSQLD]
[MYSQLD]
-----END----

Now, start the managment server:

ndb_mgmd


Next is to setup the datanodes, 

vi /etc/my.cnf (or /etc/mysql/my.cnf on debian)

Append the following:
-----BEGIN----
[mysqld]
ndbcluster
ndb-connectstring=192.168.0.3	# the IP of the MANAGMENT (THIRD) SERVER
default-storage-engine=NDBCLUSTER
[mysql_cluster]
ndb-connectstring=192.168.0.3	# the IP of the MANAGMENT (THIRD) SERVER
-----END-----

If you are going to use the mysql in a JBOSS cluster you should also 
disable the bind-address variable so the database can be connected 
from the network.
#bind-address           = 127.0.0.1

The default storage variable should be set so JBOSS automatically can
create it's tables.

Now, we make the data directory and start the storage engine:

mkdir /var/lib/mysql-cluster 
cd /var/lib/mysql-cluster 
ndbd --initial 
/etc/rc.d/init.d/mysql.server start 

Note: you should ONLY use --initial if you are either starting from scratch or 
have changed the config.ini file on the managment otherwise just use ndbd.

Do the exact samt thing for the other node.

Next step is to check that everything is working. This is done on the 
management station with the command ndbd_mgm.
In the console print 'show' and you will get something like:
----BEGIN-----
Cluster Configuration
---------------------
[ndbd(NDB)]     2 node(s)
id=2    @192.168.115.4  (Version: 4.1.11, Nodegroup: 0)
id=3    @192.168.115.5  (Version: 4.1.11, Nodegroup: 0, Master)

[ndb_mgmd(MGM)] 1 node(s)
id=1    @192.168.115.6  (Version: 4.1.11)

[mysqld(API)]   2 node(s)
id=4    @192.168.115.4  (Version: 4.1.11)
id=5    @192.168.115.5  (Version: 4.1.11)
----END-----

Which indicates that everything is ok.

TIP If you experience problems after a Mysql data node going down and
complaining about not able to connect to a socket, issue this command
on the managment concole:
PURGE STALE SESSIONS

To do a test of the setup using JDBC there is two small test script.

First create a test database on and a table 'ctest' with the following
commands:

use test; 
CREATE TABLE ctest (i INT)

Also add permissions in the database.

GRANT ALL ON test.* TO 'user'@'<yourtestscritpthost>' IDENTIFIED BY 'foo123'

To test the cluster there is two small testscripts
ant test:db that does basic functionality tests
and test:dbContiously that adds an integer every second and checks 
that it really have been added. It outputs it's data to test_out.txt 
which you can tail to see what's happening when one of the servers
is brought down.






