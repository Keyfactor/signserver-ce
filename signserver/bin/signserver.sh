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


class_name=org.signserver.cli.signserver

# discard $1 from the command line args
#shift

# J2EE server classpath
#if [ ! -n "$APPSRV_HOME" ]; then
#    if [ -n "$JBOSS_HOME" ]; then
#        APPSRV_HOME=$JBOSS_HOME
#    elif [ -n "$WEBLOGIC_HOME" ]; then
#        APPSRV_HOME=$WEBLOGIC_HOME
#    fi
#fi

#if [ -n "$APPSRV_HOME" ]; then
#    J2EE_DIR="${APPSRV_HOME}"/client
#    if [ -r "$APPSRV_HOME"/server/lib/weblogic.jar ]; then
#        echo "Using Weblogic JNDI provider..."
#        J2EE_DIR="${APPSRV_HOME}"/server/lib
#    elif [ -r "$APPSRV_HOME"/lib/appserv-rt.jar ]; then
#        echo Using Glassfish JNDI provider...
#        J2EE_DIR="${APPSRV_HOME}"/lib
#    elif [ -r "$APPSRV_HOME"/j2ee/home/oc4jclient.jar ]; then
#        echo Using Oracle JNDI provider...
#        J2EE_DIR="${APPSRV_HOME}"/j2ee/home
#    elif [ -d "$APPSRV_HOME"/runtimes ]; then
#        echo Using Websphere JNDI provider...
#        J2EE_DIR="${APPSRV_HOME}"/runtimes
#    else 
#        echo "Using JBoss JNDI provider..."
#    fi
#else
#    echo "Could not find a valid J2EE server for JNDI provider.."
#    echo "Specify a APPSRV_HOME environment variable"
#    exit 1
#fi

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
if [ ! -f ${SIGNSRV_HOME}/dist-client/signserver-cli.jar ]
then    
    if [ ! -f ${SIGNSRV_HOME}/lib/signserver-cli.jar ]
    then
        echo "You must build SIGNSERVER before using the cli, use 'ant'."
        exit 1
    fi
fi

# library classpath
CP="$SIGNSRV_HOME/dist-client/signserver-cli.jar"
for i in "${SIGNSRV_HOME}"/dist-client/lib/*.jar
do
	CP="$i":"$CP"
done
for i in "${SIGNSRV_HOME}"/lib/*.jar
do
	CP="$i":"$CP"
done
for i in "${SIGNSRV_HOME}"/lib/1.6/*.jar
do
	CP="$i":"$CP"
done
for i in "${SIGNSRV_HOME}"/lib/asm/*.jar
do
    CP="$i":"$CP"
done
for i in "${SIGNSRV_HOME}"/lib/ext/ejb/*.jar
do
	CP="$i":"$CP"
done
for i in "${SIGNSRV_HOME}"/lib/ext/james/*.jar
do
	CP="$i":"$CP"
done
CP="${SIGNSRV_HOME}/bin":"$CP"
#echo $CP

export SIGNSRV_HOME

# For Cygwin, switch paths to Windows format before running java
if $cygwin; then
  CP=`cygpath --path --windows "$CP"`
fi

exec "$JAVACMD" -cp $CP $class_name "$@"

