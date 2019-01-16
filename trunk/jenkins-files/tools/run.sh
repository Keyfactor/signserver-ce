#!/bin/bash

echo '=================== CHECKING JAVA VERSION: ================================='
java -version

echo '=================== Setting environment variables =========================='
# Set SIGNSERVER_HOME
cd signserver-ee*
export SIGNSERVER_HOME=.

# Set SIGNSERVER_NODEID
export SIGNSERVER_NODEID="magnum-ci"

echo '=================== Setup audit log ======================================='
AUDITLOG=${APPSRV_HOME}/standalone/log/signserver_audit.log
# Audit log file
echo "[SCRIPT] Removing old audit log"
rm -f signserver_audit.log
ln -s ${AUDITLOG} signserver_audit.log
rm -f ${AUDITLOG}

echo "Importing the DSSRootCA10 CA certificate to the system Java truststore"
keytool -import -keystore ${JAVA_HOME}/lib/security/cacerts -file res/test/dss10/DSSRootCA10.cacert.pem -alias DSSRootCA10 -noprompt -storepass changeit
keytool -exportcert -keystore ${JAVA_HOME}/lib/security/cacerts -alias DSSRootCA10 -file /dev/null -noprompt -storepass changeit
if [ $? -ne 0 ]; then echo "Build step 2 failed: trusting DSSRootCA10"; exit 1; fi

# Clear maintenance file
echo "Clearing maintenance file"
cat > ${SIGNSERVER_HOME}/maintenance.properties << EOF
DOWN_FOR_MAINTENANCE=false
EOF

# Start the application server
${APPSRV_HOME}/bin/standalone.sh -b 0.0.0.0 -bmanagement 0.0.0.0 &

echo '=================== Waiting for deploy ================================='

wait_for_deployment() {
    DEPLOY_SUCCESSFUL=0
	# Wait for up to 180 seconds for app to start up
	for i in {1..90} ; do
		if [ -e "${APPSRV_HOME}/standalone/deployments/signserver.ear.deployed" ] ; then
			echo "SignServer successfully started."
			DEPLOY_SUCCESSFUL=1
			break
		fi
		if [ -e "${APPSRV_HOME}/standalone/deployments/signserver.ear.failed" ] ; then
            echo "SignServer deploy failed."
            exit 1;
        fi
		echo 'waiting...'
		sleep 2
	done
    if [ "$DEPLOY_SUCCESSFUL" -ne 1 ]; then
        echo "SignServer deploy timed out." 
        exit 1;
    fi
}

wait_for_deployment
echo '=================== ant deploy-ear done and successfully deployed! ================================='

# Make sure we can communicate with SignServer or otherwise fail fast
chmod +x bin/signserver
bin/signserver getstatus brief all
if [ $? -ne 0 ]; then echo "Running SignServer CLI failed"; exit 1; fi
