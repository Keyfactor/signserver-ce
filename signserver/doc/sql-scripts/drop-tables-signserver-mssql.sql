-- Dropping tables for SignServer 6.x on Microsoft SQL
-- Version: $Id$


--
-- Drop table `AuditRecordData`
--
DROP TABLE IF EXISTS auditrecorddata;
GO

--
-- Drop table `GlobalConfigData`
--
DROP TABLE IF EXISTS globalconfigdata;
GO

--
-- Drop table `signerconfigdata`
--
DROP TABLE IF EXISTS signerconfigdata;
GO

--
-- Drop table `KeyUsageCounter`
--
DROP TABLE IF EXISTS keyusagecounter;
GO

--
-- Drop table `ArchiveData`
--
DROP TABLE IF EXISTS archivedata;
GO

--
-- Drop table `KeyData`
--
DROP TABLE IF EXISTS KeyData;
GO

--
-- Drop table `SEQUENCE`
--
DROP TABLE IF EXISTS SEQUENCE;
GO

-- End
