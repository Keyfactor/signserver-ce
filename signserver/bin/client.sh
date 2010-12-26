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
if [ ! -f ${SIGNSRV_HOME}/modules/SignServer-Client-CLI/dist/SignServer-Client-CLI.jar ]
then
	echo "You must build SignServer before using the CLI, use 'ant'."
        exit 1
fi

# For Cygwin, switch paths to Windows format before running java
if $cygwin; then
  CP=`cygpath --path --windows "$CP"`
fi

exec "$JAVACMD" -jar "${SIGNSRV_HOME}/modules/SignServer-Client-CLI/dist/SignServer-Client-CLI.jar" $@
