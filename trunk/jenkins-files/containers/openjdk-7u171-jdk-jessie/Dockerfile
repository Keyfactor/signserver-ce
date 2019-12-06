FROM openjdk:7u171-jdk-jessie

# Install Maven and Ant
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive \
    apt-get install -y maven ant \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*  
