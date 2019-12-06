FROM openjdk:7-jdk-jessie

# Install Maven, Ant and Bouncy Castle (for EC tests to not fail)
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive \
    apt-get install -y maven ant libbcprov-java \   
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*  
