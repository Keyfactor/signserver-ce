-- DDL for SignServer 3.3.x on MySQL
-- ------------------------------------------------------
-- Version: $Id$
-- Comment: 

--
-- Table structure for table `GlobalConfigurationData`
--
CREATE TABLE `GlobalConfigData` (
  `propertyKey` varchar(255) NOT NULL,
  `propertyValue` mediumtext,
  PRIMARY KEY (`propertyKey`)
) ENGINE=INNODB DEFAULT CHARSET=utf8;


--
-- Table structure for table `signerconfigdata`
--
CREATE TABLE `signerconfigdata` (
  `signerId` int(11) NOT NULL,
  `signerConfigData` mediumtext,
  PRIMARY KEY (`signerId`)
) ENGINE=INNODB DEFAULT CHARSET=utf8;


--
-- Table structure for table `KeyUsageCounter`
--
CREATE TABLE `KeyUsageCounter` (
  `keyHash` varchar(255) NOT NULL,
  `counter` bigint(20) NOT NULL,
  PRIMARY KEY (`keyHash`)
) ENGINE=INNODB DEFAULT CHARSET=utf8;


--
-- Table structure for table `ArchiveData`
--
CREATE TABLE `ArchiveData` (
  `uniqueId` varchar(255) NOT NULL,
  `time` bigint(20) NOT NULL,
  `type` int(11) NOT NULL,
  `signerid` int(11) NOT NULL,
  `archiveid` varchar(255) DEFAULT NULL,
  `requestIssuerDN` varchar(255) DEFAULT NULL,
  `requestCertSerialnumber` varchar(255) DEFAULT NULL,
  `requestIP` varchar(255) DEFAULT NULL,
  `archiveData` mediumtext,
  `dataEncoding` int(11) DEFAULT NULL,
  PRIMARY KEY (`uniqueId`)
) ENGINE=INNODB DEFAULT CHARSET=utf8;


--
-- Table structure for table `enckeydata`
--
CREATE TABLE `enckeydata` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `workerId` int(11) NOT NULL,
  `encKeyRef` varchar(255) DEFAULT NULL,
  `inUse` bit(1) NOT NULL,
  `usageStarted` datetime DEFAULT NULL,
  `usageEnded` datetime DEFAULT NULL,
  `numberOfEncryptions` bigint(20) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=INNODB AUTO_INCREMENT=122 DEFAULT CHARSET=utf8;


--
-- Table structure for table `groupkeydata`
--
CREATE TABLE `groupkeydata` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `documentID` varchar(255) DEFAULT NULL,
  `workerId` int(11) NOT NULL,
  `encryptedData` blob,
  `creationDate` datetime DEFAULT NULL,
  `firstUsedDate` datetime DEFAULT NULL,
  `lastFetchedDate` datetime DEFAULT NULL,
  `encKeyRef` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=INNODB AUTO_INCREMENT=128 DEFAULT CHARSET=utf8;


--
-- Table structure for table `SEQUENCE`
--
CREATE TABLE `SEQUENCE` (
  `SEQ_NAME` varchar(50) NOT NULL,
  `SEQ_COUNT` decimal(38,0) DEFAULT NULL,
  PRIMARY KEY (`SEQ_NAME`)
) ENGINE=INNODB DEFAULT CHARSET=utf8;

--
-- Table structure for table 'AuditRecordData'
--
CREATE TABLE AuditRecordData (
    pk VARCHAR(250) BINARY NOT NULL,
    additionalDetails LONGTEXT,
    authToken VARCHAR(250) BINARY NOT NULL,
    customId VARCHAR(250) BINARY,
    eventStatus VARCHAR(250) BINARY NOT NULL,
    eventType VARCHAR(250) BINARY NOT NULL,
    module VARCHAR(250) BINARY NOT NULL,
    nodeId VARCHAR(250) BINARY NOT NULL,
    rowProtection LONGTEXT,
    rowVersion INT(11) NOT NULL,
    searchDetail1 VARCHAR(250) BINARY,
    searchDetail2 VARCHAR(250) BINARY,
    sequenceNumber BIGINT(20) NOT NULL,
    service VARCHAR(250) BINARY NOT NULL,
    timeStamp BIGINT(20) NOT NULL,
    PRIMARY KEY (pk)
) ENGINE=INNODB DEFAULT CHARSET=utf8;


-- End
