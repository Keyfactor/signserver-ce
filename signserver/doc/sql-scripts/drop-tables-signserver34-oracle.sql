-- Dropping tables for SignServer 3.3.x on Oracle
-- ------------------------------------------------------
-- Version: $Id$
-- Comment: 


DROP TABLE "AccessRulesData";

DROP TABLE "AuthorizationTreeUpdateData";

DROP TABLE "AdminEntityData";

DROP TABLE "AdminGroupData";

DROP TABLE "AuditRecordData";

--
-- Table structure for table `GlobalConfigurationData`
--
DROP TABLE "GLOBALCONFIG";


--
-- Table structure for table `signerconfigdata`
--
DROP TABLE "SIGNERCONFIGDATA";


--
-- Table structure for table `KeyUsageCounter`
--
DROP TABLE "KEYUSAGECOUNTER";


--
-- Table structure for table `ArchiveData`
--
DROP TABLE "ARCHIVEDATA";


--
-- Table structure for table `enckeydata`
--
DROP TABLE "ENCKEYDATA";


--
-- Table structure for table `groupkeydata`
--
DROP TABLE "GROUPKEYDATA";


--
-- Table structure for table `SEQUENCE`
--
CREATE SEQUENCE "HIBERNATE_SEQUENCE"  MINVALUE 1 MAXVALUE 999999999999999999999999999 INCREMENT BY 1;


-- End
