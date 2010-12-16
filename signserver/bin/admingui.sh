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


class_name=org.signserver.admin.gui.SignServerAdminGUIApplication
MAIN_JAR=SignServer-AdminGUI.jar

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
if [ ! -f ${SIGNSRV_HOME}/modules/SignServer-AdminGUI/dist/${MAIN_JAR} ]
then
	echo "You must build SignServer before using the cli, use 'ant'."
        exit 1
fi

#CP="${SIGNSRV_HOME}/bin/jndi.properties":"$CP"

if [ -r "$APPSRV_HOME"/lib/appserv-rt.jar ]; then
    echo Using GlassFish JNDI provider...
    CP=$CP:"$APPSRV_HOME"/lib/appserv-rt.jar
else
    echo "Assuming JBoss JNDI provider..."
    CP=$CP:"$APPSRV_HOME/client/jbossall-client.jar"
fi

CP="$CP":"$SIGNSRV_HOME/modules/SignServer-AdminGUI/dist/${MAIN_JAR}"



export SIGNSRV_HOME

# For Cygwin, switch paths to Windows format before running java
if $cygwin; then
  CP=`cygpath --path --windows "$CP"`
fi

exec "$JAVACMD" -cp $CP $class_name "$@" -connectfile modules/SignServer-AdminGUI/connect.properties -defaultconnectfile modules/SignServer-AdminGUI/connect.properties
