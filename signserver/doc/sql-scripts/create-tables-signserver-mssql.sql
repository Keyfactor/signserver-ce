-- DDL for SignServer 6.x on Microsoft SQL
-- ------------------------------------------------------
-- Version: $Id$
-- Comment:


CREATE TABLE AuditRecordData (
    pk VARCHAR(256) NOT NULL,
    additionalDetails TEXT,
    authToken VARCHAR(256) NOT NULL,
    customId VARCHAR(256),
    eventStatus VARCHAR(256) NOT NULL,
    eventType VARCHAR(256) NOT NULL,
    module VARCHAR(256) NOT NULL,
    nodeId VARCHAR(256) NOT NULL,
    rowProtection TEXT,
    rowVersion INTEGER NOT NULL,
    searchDetail1 VARCHAR(256),
    searchDetail2 VARCHAR(256),
    sequenceNumber BIGINT NOT NULL,
    service VARCHAR(256) NOT NULL,
    timeStamp BIGINT NOT NULL,
    PRIMARY KEY (pk)
);  

--
-- Table structure for table `GlobalConfigurationData`
--
CREATE TABLE GlobalConfigData (
    propertyKey varchar(256) NOT NULL,
    propertyValue TEXT,
    PRIMARY KEY (propertyKey)
);

--
-- Table structure for table `signerconfigdata`
--
CREATE TABLE signerconfigdata (
    signerId INTEGER NOT NULL,
    signerName VARCHAR(255),
    signerType int DEFAULT NULL,
    signerConfigData TEXT,
    PRIMARY KEY (signerId)
);

--
-- Table structure for table `KeyUsageCounter`
--
CREATE TABLE KeyUsageCounter (
    keyHash varchar(255) NOT NULL,
    counter BIGINT NOT NULL,
    PRIMARY KEY (keyHash)
);

--
-- Table structure for table `ArchiveData`
--
CREATE TABLE ArchiveData (
    uniqueId varchar(255) NOT NULL,
    time BIGINT NOT NULL,
    type INTEGER NOT NULL,
    signerid INTEGER NOT NULL,
    archiveid varchar(255) DEFAULT NULL,
    requestIssuerDN varchar(255) DEFAULT NULL,
    requestCertSerialnumber varchar(255) DEFAULT NULL,
    requestIP varchar(255) DEFAULT NULL,
    archiveData TEXT,
    dataEncoding INTEGER DEFAULT NULL,
    PRIMARY KEY (uniqueId)
);

--
-- Table structure for table `SEQUENCE`
--
CREATE TABLE SEQUENCE (
    SEQ_NAME varchar(50) NOT NULL,
    SEQ_COUNT decimal(38,0) DEFAULT NULL,
    PRIMARY KEY (SEQ_NAME)
);

--
-- Table structure for table `KeyData`
--
CREATE TABLE KeyData (
    keyAlias varchar(255) NOT NULL,
    wrappingKeyAlias varchar(255) NOT NULL,
    wrappingCipher BIGINT NOT NULL,
    keyData NVARCHAR NOT NULL,
    certData NVARCHAR NOT NULL,
    PRIMARY KEY (keyAlias)
);
