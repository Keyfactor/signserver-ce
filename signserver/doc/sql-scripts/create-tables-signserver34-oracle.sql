-- DDL for SignServer 3.3.x on Oracle
-- ------------------------------------------------------
-- Version: $Id$
-- Comment: These definitions should work for SignServer 3.3.x, Oracle 10.x and the JDBC driver version 10.2.0.1.0.
-- TODO: Update the versions above with what we tested with

CREATE TABLE AccessRulesData (
    pK NUMBER(10) NOT NULL,
    accessRule VARCHAR2(255 byte) NOT NULL,
    isRecursive NUMBER(1) NOT NULL,
    rowProtection CLOB,
    rowVersion NUMBER(10) NOT NULL,
    rule NUMBER(10) NOT NULL,
    AdminGroupData_accessRules NUMBER(10),
    PRIMARY KEY (pK)
);

CREATE TABLE AdminEntityData (
    pK NUMBER(10) NOT NULL,
    cAId NUMBER(10) NOT NULL,
    matchType NUMBER(10) NOT NULL,
    matchValue VARCHAR2(255 byte),
    matchWith NUMBER(10) NOT NULL,
    rowProtection CLOB,
    rowVersion NUMBER(10) NOT NULL,
    tokenType VARCHAR2(255 byte),
    AdminGroupData_adminEntities NUMBER(10),
    PRIMARY KEY (pK)
);

CREATE TABLE AdminGroupData (
    pK NUMBER(10) NOT NULL,
    adminGroupName VARCHAR2(255 byte) NOT NULL,
    rowProtection CLOB,
    rowVersion NUMBER(10) NOT NULL,
    PRIMARY KEY (pK)
);

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

CREATE TABLE AuthorizationTreeUpdateData (
    pK NUMBER(10) NOT NULL,
    authorizationTreeUpdateNumber NUMBER(10) NOT NULL,
    rowProtection CLOB,
    rowVersion NUMBER(10) NOT NULL,
    PRIMARY KEY (pK)
);


--
-- Table structure for table `GlobalConfigurationData`
--
CREATE TABLE "GLOBALCONFIG" (
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
-- Table structure for table `enckeydata`
--
CREATE TABLE "ENCKEYDATA" (
	"ID" NUMBER(19,0) NOT NULL, 
	"ENCKEYREF" VARCHAR2(255 CHAR), 
	"INUSE" NUMBER(1,0) NOT NULL, 
	"NUMBEROFENCRYPTIONS" NUMBER(19,0) NOT NULL, 
	"USAGEENDED" TIMESTAMP (6), 
	"USAGESTARTED" TIMESTAMP (6), 
	"WORKERID" NUMBER(10,0) NOT NULL, 
	PRIMARY KEY ("ID")
);


--
-- Table structure for table `groupkeydata`
--
CREATE TABLE "GROUPKEYDATA" (
	"ID" NUMBER(19,0) NOT NULL, 
	"CREATIONDATE" TIMESTAMP (6), 
	"DOCUMENTID" VARCHAR2(255 CHAR), 
	"ENCKEYREF" VARCHAR2(255 CHAR), 
	"ENCRYPTEDDATA" BLOB, 
	"FIRSTUSEDDATE" TIMESTAMP (6), 
	"LASTFETCHEDDATE" TIMESTAMP (6), 
	"WORKERID" NUMBER(10,0) NOT NULL, 
	PRIMARY KEY ("ID")
);


--
-- Table structure for table `SEQUENCE`
--
CREATE SEQUENCE "HIBERNATE_SEQUENCE"  MINVALUE 1 MAXVALUE 999999999999999999999999999 INCREMENT BY 1;

alter table AccessRulesData add constraint FKABB4C1DFDBBC970 foreign key (AdminGroupData_accessRules) references AdminGroupData;

alter table AdminEntityData add constraint FKD9A99EBCB3A110AD foreign key (AdminGroupData_adminEntities) references AdminGroupData;

-- End
