# Use latest jboss/base-jdk:8 image as the base
FROM openjdk:11-jdk-stretch

USER root

# Install Maven and Ant
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive \
    apt-get install -y maven ant strace openssl mariadb-client mariadb-server fakeroot alien gnupg2 dpkg-sig\
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

ENV JAVA_OPTS="-Xms64M -Xmx256M"
ENV ANT_OPTS="-Xms64M -Xmx64M"
ENV MAVEN_OPTS="-Xms128M -Xmx384M"

RUN groupadd -g 1000 user
RUN useradd --uid 1000 -g 1000 user
RUN mkdir /opt/jboss

# Set the appserver env variables
ENV APPSRV_VERSION 7.2.0
ENV APPSRV_FOLDER jboss-eap-7.2
ENV APPSRV_SHA256 657cbd07aa87dcf4dc4d8ceb0cdd6e4414a156a75cf14ce2b2a79ade36463482
ENV APPSRV_ZIP jboss-eap-$APPSRV_VERSION.zip
ENV APPSRV_HOME /opt/jboss/$APPSRV_FOLDER

ENV ANT_OPTS="-Xms64M -Xmx256M"
ENV JAVA_OPTS="-Xms64M -Xmx256M"

# TODO: parameterize this
ENV JAVA_HOME /usr/local/openjdk-11

# Make Sure the SafeNet emulator will not generate a fixed key
# for a given key size/spec
ENV ET_PTKC_SW_AUTOSEEDRNG true

# Eracom emulator
ENV ERACOM_RPM=ETcpsdk-3.33.00-1.x86_64.rpm
ENV ERACOM_SHA256=9ab17a4380771382984285ae59b0405f32c3436a7d154a82a897132940eacbc0

# Emulator prepared setup
ENV CRYPTOKI_ZIP=cryptoki.zip
ENV CRYPTOKI_SHA256=dad7027b5ff1ea615095a4195d7388b6b0aab590a08138d34e23cb9ecaa99cc1

# P11 test config variables
ENV LIBCRYPTOKI="/opt/ETcpsdk/lib/linux-x86_64/libcryptoki.so"
ENV P11SLOT="2"
ENV P11SLOTINDEX="9"
ENV P11PIN="foo123"
ENV P11KEY="mykey001"

# Database JDBC drivers
ENV MARIADB_DRIVER_JAR="mariadb-java-client-1.1.5.jar"

# Make Java keystore read/write for all users
RUN java -version && ls -l /usr/lib/jvm/ && ls -l /usr/local/openjdk-11 && chmod 666 $JAVA_HOME/lib/security/cacerts

WORKDIR /root

COPY binaries/$APPSRV_ZIP ./
COPY binaries/$ERACOM_RPM ./
COPY binaries/$CRYPTOKI_ZIP ./
COPY binaries/$MARIADB_CLIENT_JAR ./

# Assume /binaries is mounted from the pipeline
# Add the appserver distribution to /opt, and make jboss the owner of the extracted ZIP content
# Make sure the distribution is available from a well-known place
RUN cd $HOME \
    && ls \
    && pwd \
    && sha256sum $APPSRV_ZIP | grep $APPSRV_SHA256 \
    && unzip $APPSRV_ZIP \
    && mv $APPSRV_FOLDER /opt/jboss/ \
    && rm $APPSRV_ZIP \
    && chown -R user:0 /opt/jboss \
    && chmod -R a+rw /opt/jboss              
# TODO only chmod g+rw but make sure it works to run

# Ensure signals are forwarded to the JVM process correctly for graceful shutdown
ENV LAUNCH_JBOSS_IN_BACKGROUND true

# Fix locale
#RUN yum reinstall -q -y glibc-common \
#    && localedef -i en_US -f UTF-8 en_US.UTF-8 \
#    && echo "LANG=en_US.utf8" >> /etc/locale.conf \
#    && yum clean all

# Install HSM emulator
RUN cd $HOME \
    && sha256sum $ERACOM_RPM | grep $ERACOM_SHA256 \
    && fakeroot alien $ERACOM_RPM \
    && dpkg -i etcpsdk_3.33.00-2_amd64.deb \
    && ln -s /opt/ETcpsdk/lib/linux-x86_64/libctsw.so /opt/ETcpsdk/lib/linux-x86_64/libcryptoki.so \
    && rm $ERACOM_RPM \
    && rm etcpsdk_3.33.00-2_amd64.deb

ENV LANG en_US.UTF-8

# Set LD_LIBRARY_PATH for SafeNet
ENV LD_LIBRARY_PATH /opt/ETcpsdk/lib/linux-x86_64

# Unpack HSM emulator setup (couldn't get running
# ctconf setup commands from scratch working,
# requires interactive input of PIN codes)
RUN cd $HOME \
    && sha256sum $CRYPTOKI_ZIP | grep $CRYPTOKI_SHA256 \
    && mkdir -p /opt/eracom \
    && cp $CRYPTOKI_ZIP /opt/eracom \
    && chmod a+rw /opt/eracom/$CRYPTOKI_ZIP \
    && rm $CRYPTOKI_ZIP \
    && echo "pwd: $HOME" && ls -la \
    && echo "home jboss: " && ls -la /opt/jboss \
    && echo "cryptoki lib dir: " && ls -la /opt/ETcpsdk/lib/linux-x86_64

# put the JDBC driver in /opt/jboss for the pipeline to install in the correct place
RUN cd $HOME \
    && cp $MARIADB_DRIVER_JAR /opt/jboss

USER user

# Set the default command to run on boot
# This will boot the appserver in the standalone mode and bind to all interface
CMD ["$APPSRV_HOME/bin/standalone.sh", "-b", "0.0.0.0"]
