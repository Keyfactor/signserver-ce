-- Dropping tables for SignServer 3.5.x on Postgres


--
-- Drop table `AuditRecordData`
--
DROP TABLE IF EXISTS auditrecorddata;

--
-- Drop table `GlobalConfigData`
--
DROP TABLE IF EXISTS globalconfigdata;

--
-- Drop table `signerconfigdata`
--
DROP TABLE IF EXISTS signerconfigdata;

--
-- Drop table `KeyUsageCounter`
--
DROP TABLE IF EXISTS keyusagecounter;


--
-- Drop table `ArchiveData`
--
DROP TABLE IF EXISTS archivedata;


--
-- Drop table `SEQUENCE`
--
DROP SEQUENCE IF EXISTS hibernate_sequence;


-- End
