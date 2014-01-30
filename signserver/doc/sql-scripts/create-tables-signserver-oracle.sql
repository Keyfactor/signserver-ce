-- DDL for SignServer 3.5.x on Oracle
-- ------------------------------------------------------
-- Version: $Id$
-- Comment:


--
-- Table structure for table `AuditRecordData`
--
CREATE TABLE AuditRecordData (
    pk VARCHAR2(255 byte) NOT NULL,
    additionalDetails CLOB,
    authToken VARCHAR2(255 byte) NOT NULL,
    customId VARCHAR2(255 byte),
    eventStatus VARCHAR2(255 byte) NOT NULL,
    eventType VARCHAR2(255 byte) NOT NULL,
    module VARCHAR2(255 byte) NOT NULL,
    nodeId VARCHAR2(255 byte) NOT NULL,
    rowProtection CLOB,
    rowVersion NUMBER(10) NOT NULL,
    searchDetail1 VARCHAR2(255 byte),
    searchDetail2 VARCHAR2(255 byte),
    sequenceNumber NUMBER(19) NOT NULL,
    service VARCHAR2(255 byte) NOT NULL,
    timeStamp NUMBER(19) NOT NULL,
    PRIMARY KEY (pk)
);


--
-- Table structure for table `GlobalConfigurationData`
--
CREATE TABLE "GLOBALCONFIGDATA" (
	"PROPERTYKEY" VARCHAR2(255 CHAR) NOT NULL, 
	"PROPERTYVALUE" CLOB, 
	PRIMARY KEY ("PROPERTYKEY")
);


--
-- Table structure for table `signerconfigdata`
--
CREATE TABLE "SIGNERCONFIGDATA" (
	"SIGNERID" NUMBER(10,0) NOT NULL, 
	"SIGNERCONFIGDATA" CLOB, 
	PRIMARY KEY ("SIGNERID")
);


--
-- Table structure for table `KeyUsageCounter`
--
CREATE TABLE "KEYUSAGECOUNTER" (
	"KEYHASH" VARCHAR2(255 CHAR) NOT NULL, 
	"COUNTER" NUMBER(19,0) NOT NULL, 
 	PRIMARY KEY ("KEYHASH")
);


--
-- Table structure for table `ArchiveData`
--
CREATE TABLE "ARCHIVEDATA" (
	"UNIQUEID" VARCHAR2(255 CHAR) NOT NULL, 
	"ARCHIVEDATA" CLOB, 
	"ARCHIVEID" VARCHAR2(255 CHAR), 
	"REQUESTCERTSERIALNUMBER" VARCHAR2(255 CHAR), 
	"REQUESTIP" VARCHAR2(255 CHAR), 
	"REQUESTISSUERDN" VARCHAR2(255 CHAR), 
	"SIGNERID" NUMBER(10,0) NOT NULL, 
	"TIME" NUMBER(19,0) NOT NULL, 
	"TYPE" NUMBER(10,0) NOT NULL, 
    "DATAENCODING" NUMBER(10,0), 
	PRIMARY KEY ("UNIQUEID")
);


--
-- Table structure for table `SEQUENCE`
--
CREATE SEQUENCE "HIBERNATE_SEQUENCE"  MINVALUE 1 MAXVALUE 999999999999999999999999999 INCREMENT BY 1;


-- End
