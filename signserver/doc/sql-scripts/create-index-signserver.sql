-- version: $Id$

-- Selecting log entries when verifying/exporting IntegrityProtectedDevice logs:
CREATE UNIQUE INDEX auditrecorddata_idx2 ON AuditRecordData (nodeId,sequenceNumber);
-- Selecting log entries from IntegrityProtectedDevice logs in the AdminGUI is usually
-- done using time constraints.
CREATE INDEX auditrecorddata_idx3 ON AuditRecordData (timeStamp);
