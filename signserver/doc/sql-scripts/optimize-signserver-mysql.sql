-- version: $Id$

-- There is normally no use for the primary key
ALTER TABLE AuditRecordData DROP PRIMARY KEY;
-- Partitioning to allow easy reclaim of space after export and delete of old audit log.
-- If you never plan on removing Security Events Audit log, this can be skipped.
-- This example will divide the stored data by for a few nodes with up to 250M rows in
-- in each partition.
-- ALTER TABLE AuditRecordData REMOVE PARTITIONING;
-- ALTER TABLE AuditRecordData PARTITION BY RANGE( sequenceNumber ) SUBPARTITION BY KEY( nodeId ) (
--   PARTITION p01 VALUES LESS THAN (250000000) (
--     SUBPARTITION s01a, SUBPARTITION s01b,
--     SUBPARTITION s01c, SUBPARTITION s01d ),
--   PARTITION p02 VALUES LESS THAN (500000000) (
--     SUBPARTITION s02a, SUBPARTITION s02b,
--     SUBPARTITION s02c, SUBPARTITION s02d ),
--   PARTITION p03 VALUES LESS THAN (750000000) (
--    SUBPARTITION s03a, SUBPARTITION s03b,
--     SUBPARTITION s03c, SUBPARTITION s03d ),
--   PARTITION p05 VALUES LESS THAN MAXVALUE (
--     SUBPARTITION s04a, SUBPARTITION s04b,
--     SUBPARTITION s04c, SUBPARTITION s04d )
-- );


-- Compression of large tables to increase relative in-memory caching
ALTER TABLE AuditRecordData row_format=compressed key_block_size=4;
