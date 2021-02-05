FROM centos:7
# Consider building this with "--disable-content-trust=false --pull" e.g.
#   docker build --disable-content-trust=false --pull -t pk-test/patchjdk . && docker run -it --rm -v /tmp:/build/artifacts pk-test/patchjdk

RUN \
    yum install -y java-1.8.0-openjdk java-1.8.0-openjdk-devel && \
    yum install -y java-1.8.0-openjdk-src && \
    yum install -y make unzip zip patch which && \
    yum clean all && \
    rm -rf /var/cache/yum

WORKDIR /root

#ADD run.sh /build/
COPY binaries/openJDK8-sunec.patch ./
COPY binaries/openJDK8-sunpkcs11.patch ./

RUN groupadd -g 1000 user
RUN useradd --uid 1000 -g 1000 user
USER user


