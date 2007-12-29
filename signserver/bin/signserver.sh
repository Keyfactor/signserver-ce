#!/usr/bin/env bash

# OS specific support.
cygwin=false;
case "`uname`" in
  CYGWIN*) cygwin=true ;;
esac

# Check that JAVA_HOME is set
if [ -f $JAVA_HOME ]; then
    echo "You must set JAVA_HOME before running the SIGNSERVER cli."
    exit 1
fi

	class_name=org.signserver.cli.signserver

# discard $1 from the command line args
#shift

# J2EE server classpath
if [ -n "$JBOSS_HOME" ]; then
    echo "Using JBoss JNDI provider..."
    J2EE_DIR="${JBOSS_HOME}"/client
elif [ -n "$WEBLOGIC_HOME" ]; then
    echo "Using Weblogic JNDI provider..."
    J2EE_DIR="${WEBLOGIC_HOME}"/server/lib
else
    echo "Could not find a valid J2EE server for JNDI provider.."
    echo "Specify a JBOSS_HOME or WEBLOGIC_HOME environment variable"
    exit 1
fi

SIGNSERVER_HOME="`dirname $0`/.."
# Check that classes exist
if [ ! -d ${SIGNSERVER_HOME}/tmp/bin/classes ]
then    
        echo "You must build SIGNSERVER before using the cli, use 'ant'."
        exit 1
fi

# library classpath
CP="$SIGNSERVER_HOME/tmp/bin/classes"
for i in "${J2EE_DIR}"/*.jar
do
	CP="$i":"$CP"
done
for i in "${SIGNSERVER_HOME}"/lib/*.jar
do
	CP="$i":"$CP"
done
for i in "${SIGNSERVER_HOME}"/lib/1.5/*.jar
do
	CP="$i":"$CP"
done
for i in "${SIGNSERVER_HOME}"/lib/ejb/*.jar
do
	CP="$i":"$CP"
done
for i in "${SIGNSERVER_HOME}"/lib/james/*.jar
do
	CP="$i":"$CP"
done

CP=$CP:$EJBCA_HOME/bin


# For Cygwin, switch paths to Windows format before running java
if $cygwin; then
  CP=`cygpath --path --windows "$CP"`
fi

exec "$JAVA_HOME/bin/java" -cp $CP $class_name "$@"

