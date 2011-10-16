#!/usr/bin/env bash

# OS specific support.
cygwin=false;
case "`uname`" in
  CYGWIN*) cygwin=true ;;
esac

JAVACMD=`which java`
# Check that JAVA_HOME is set
if [ ! -n "$JAVA_HOME" ]; then
    if [ ! -n "$JAVACMD" ]
    then
        echo "You must set JAVA_HOME before running the SignServer cli."
        exit 1
    fi
else
    JAVACMD=$JAVA_HOME/bin/java
fi


class_name=org.signserver.client.cli.Main
MAIN_JAR=SignServer-Client-CLI.jar

# discard $1 from the command line args
#shift

# J2EE server classpath
if [ ! -n "$APPSRV_HOME" ]; then
    if [ -n "$JBOSS_HOME" ]; then
        APPSRV_HOME=$JBOSS_HOME
    elif [ -n "$WEBLOGIC_HOME" ]; then
        APPSRV_HOME=$WEBLOGIC_HOME
    fi
fi

if [ ! -n "$APPSRV_HOME" ]; then
    echo "To connect to a local SignServer please set APPSRV_HOME first."
fi

if [ ! -n "${SIGNSERVER_HOME}" ]; then
  if [ -f /etc/signserver/signservermgmt.env ]; then
     . /etc/signserver/signservermgmt.env
  fi
  if [ -f /etc/mailsigner/mailsignermgmt.env ]; then
     . /etc/mailsigner/mailsignermgmt.env
  fi
  if [ -f /usr/share/signserver/bin/signserver.sh ]; then
     SIGNSRV_HOME=/usr/share/signserver
  fi
  if [ -f /opt/signserver/bin/signserver.sh ]; then
     SIGNSRV_HOME=/opt/signserver
  fi
  if [ -f /usr/local/signserver/bin/signserver.sh ]; then
     SIGNSRV_HOME=/usr/local/signserver
  fi
  if [ -f ./signserver.sh ]; then
     SIGNSRV_HOME=..
  fi
  if [ -f bin/signserver.sh ]; then
     SIGNSRV_HOME=.
  fi
else
  SIGNSRV_HOME=$SIGNSERVER_HOME
fi 

# Check that classes exist
if [ ! -f ${SIGNSRV_HOME}/dist-client/${MAIN_JAR} ]
then
	echo "You must build SignServer Client CLI first."
        exit 1
fi

#CP="${SIGNSRV_HOME}/bin/jndi.properties":"$CP"

if [ -r "$APPSRV_HOME"/lib/appserv-rt.jar ]; then
    echo "Using GlassFish JNDI provider..." 1>&2
    CP=$CP:"$APPSRV_HOME"/lib/appserv-rt.jar
else
    echo "Assuming JBoss JNDI provider..." 1>&2
    CP=$CP:"$APPSRV_HOME/client/jbossall-client.jar"
fi

#CP="$CP":"$SIGNSRV_HOME/dist-client/${MAIN_JAR}"

CP="$CP:$SIGNSRV_HOME/lib/log4j.jar:$SIGNSRV_HOME/lib/ext/commons-cli-1.0.jar:$SIGNSRV_HOME/lib/1.6/bcprov-jdk.jar:$SIGNSRV_HOME/lib/cert-cvc.jar:$SIGNSRV_HOME/lib/commons-lang-2.4.jar:$SIGNSRV_HOME/lib/ejbca-util.jar:$SIGNSRV_HOME/lib/1.6/bctsp-jdk.jar:$SIGNSRV_HOME/lib/1.6/bcmail-jdk.jar:$SIGNSRV_HOME/dist-client/timestampclient/timeStampClient.jar:$SIGNSRV_HOME/modules/SignServer-Common/dist/SignServer-Common.jar:$SIGNSRV_HOME/modules/SignServer-Client-SigningAndValidationAPI/dist/SignServer-Client-SigningAndValidationAPI.jar:$SIGNSRV_HOME/modules/SignServer-Client-SignServerWS/dist/SignServer-Client-SignServerWS.jar:$SIGNSRV_HOME/modules/SignServer-ejb-SignServerWS/dist/SignServer-ejb-SignServerWS.jar:$SIGNSRV_HOME/modules/SignServer-Client-ValidationCLI/dist/SignServer-Client-ValidationCLI.jar:$SIGNSRV_HOME/lib/reports/jcommon-1.0.12.jar:$SIGNSRV_HOME/lib/reports/jfreechart-1.0.9.jar:$SIGNSRV_HOME/lib/module/pdfsigner/itext/itext.jar:$SIGNSRV_HOME/modules/SignServer-Client-CLI/dist/SignServer-Client-CLI.jar"


export SIGNSRV_HOME

# For Cygwin, switch paths to Windows format before running java
if $cygwin; then
  CP=`cygpath --path --windows "$CP"`
fi

exec "$JAVACMD" -cp $CP $class_name "$@"
