/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.database.audit;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.SortedSet;
import java.util.concurrent.ConcurrentSkipListSet;

import javax.persistence.EntityManager;
import javax.persistence.Query;

import org.apache.log4j.Logger;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.audit.AuditLogReportElem;
import org.cesecore.audit.audit.AuditLogValidationReport;
import org.cesecore.audit.impl.integrityprotected.AuditRecordData;
import org.cesecore.config.ConfigurationHolder;
import org.cesecore.dbprotection.DatabaseProtectionException;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.util.query.Criteria;
import org.cesecore.util.query.QueryCriteria;
import org.cesecore.util.query.QueryGenerator;

/**
 * Verification of audit logs with direct database access.
 *
 * The index
 *  "CREATE UNIQUE INDEX auditrecorddata_idx1 ON AuditRecordData (nodeId,timeStamp,sequenceNumber);"
 * should be present for proper validation and export performance.
 *
 * @version $Id: IntegrityProtectedAuditReader.java 15950 2012-11-30 12:08:36Z primelars $
 */
public class IntegrityProtectedAuditReader {

	private static final Logger log = Logger.getLogger(IntegrityProtectedAuditReader.class);

	private final EntityManager entityManager;
	private final List<String> nodes;
	private final long timestampFrom;
	private final long timestampTo;
	private final int maxFetchSize;
	private final AuditLogValidationReport auditLogValidationReport = new AuditLogValidationReport();
	private long startIndex = 0;
	private int currentNodeIndex = 0;
	private long lastSeqNrFromPreviousChunk = -1;// The first sequence number should always be 0. -1 is the number before it. Used when no previous chunk.

        private final Map<String, Long> startSequences;
        
	/**
	 * Creates a new instance of this reader that can be used to fetch verified audit log data.
	 * @param entityManager
	 * @param timestampFrom
	 * @param timestampTo
	 * @param maxFetchSize
	 */
        public IntegrityProtectedAuditReader(final EntityManager entityManager, long timestampFrom, long timestampTo, int maxFetchSize) {
            this(entityManager, timestampFrom, timestampTo, maxFetchSize, null);
        }
                
        /**
         * Creates an new instance of the IntegrityProtectedAuditReader.
         * @param entityManager
         * @param timestampFrom
         * @param timestampTo
         * @param maxFetchSize
         * @param startSequences Map from nodeId to the start index. Only the 
         * nodes listed will be considered or null if all nodes should be used 
         * and start from 0.
         */
	public IntegrityProtectedAuditReader(final EntityManager entityManager, long timestampFrom, long timestampTo, int maxFetchSize, Map<String, Long> startSequences) {
		this.entityManager = entityManager;
		this.timestampFrom = timestampFrom;
		this.timestampTo = timestampTo;
		this.maxFetchSize = maxFetchSize;
                
                final List<String> availableNodes = getNodeIds();
                if (startSequences == null) {
                    startSequences = new HashMap<>();
                    for (String node : availableNodes) {
                        startSequences.put(node, 0L);
                    }   
                }
                this.startSequences = startSequences;
		// We fetch all the nodes, even if there are no events for a node in this time-span
		this.nodes = new ArrayList<>(startSequences.keySet());
                
		// Make sure that we really do verify and throw detectable DatabaseProtectionError if the verification fails.
		ConfigurationHolder.instance();
		ConfigurationHolder.updateConfiguration("databaseprotection.enableverify.AuditRecordData", "true");
		ConfigurationHolder.updateConfiguration("databaseprotection.erroronverifyfail", "true");
                
                this.currentNodeIndex = 0;
                if (nodes.size() < 1) {
                    this.lastSeqNrFromPreviousChunk = -1;
                } else {
                    this.lastSeqNrFromPreviousChunk = startSequences.get(this.nodes.get(this.currentNodeIndex)) - 1;
                }
	}

	public boolean isDone() {
		return this.nodes.size()<=this.currentNodeIndex;
	}

	/** @return the audit log validation report after all the data has been fetched and verified. */
	public AuditLogValidationReport getAuditLogValidationReport() {
		return this.auditLogValidationReport;
	}

        /** @return the Node id (name) **/
	public String getNodeId() {
		return this.nodes.get(this.currentNodeIndex);
	}
	/**
	 * Fetch and verify the next chunk of AuditRecordData rows.
	 * @return number of rows in last chunk
	 */
	public int getNextVerifiedChunk() {
		if (log.isDebugEnabled() && this.entityManager.getTransaction().isActive()) {
			log.debug("It might not be suitable to run this in a transaction, since these operations can easily time out and there is no need for updates.");
		}
		if (isDone()) {
			return 0;
		}
		final SortedSet<Long> sequenceNrSet = new ConcurrentSkipListSet<>();
		sequenceNrSet.add(this.lastSeqNrFromPreviousChunk);
		final int nrRead = read(startSequences.get(this.nodes.get(this.currentNodeIndex)) - 1, this.startIndex, this.maxFetchSize, true, sequenceNrSet);
		if ( nrRead<1 ) {// nothing more to read from this node
			this.startIndex = 0;
			this.currentNodeIndex++;
                        if (isDone()) {
                            return 0;
                        }
			this.lastSeqNrFromPreviousChunk = startSequences.get(this.nodes.get(this.currentNodeIndex)) - 1;
			return getNextVerifiedChunk();
		}
		this.lastSeqNrFromPreviousChunk = checkForMissingSequenceNrs(sequenceNrSet);
		this.startIndex += nrRead;
		return nrRead;
	}
	private long checkForMissingSequenceNrs(final SortedSet<Long> sequenceNrSet) {
		final long highestNr = sequenceNrSet.last();
		final long lowestNr = sequenceNrSet.first();
		if ( highestNr+1==lowestNr+sequenceNrSet.size() ) {
			sequenceNrSet.clear();// all sequence number must exist if this size.
			return highestNr;// done
		}
		// some rows must be missing. find out which
		long currLowNr = lowestNr;
		while ( true ) {
			sequenceNrSet.remove(currLowNr);
			if ( sequenceNrSet.isEmpty() ) {
				break; // no more rows
			}
			final long nextLowestNr = sequenceNrSet.first();
			if ( currLowNr+1!=nextLowestNr ) {
				final String msg = "Database integrity protection breach for row nodeId="+this.nodes.get(this.currentNodeIndex)
						+ " lastVerifiedSequenceNumber="+currLowNr + " thisSequenceNumber="+nextLowestNr;
				//log.warn(msg);
				this.auditLogValidationReport.error(new AuditLogReportElem(currLowNr, nextLowestNr, msg));
			}
			currLowNr = nextLowestNr;
		}
		return highestNr;
	}
	private int read(final long sequenceStart, final long startPosition, final int maxResult, final boolean firstTime, final SortedSet<Long> sequenceNrSet) {
		if ( maxResult<1 ) {
			return 0;// length of chunk must be >0 to read something
		}
		if (log.isDebugEnabled() && this.entityManager.getTransaction().isActive()) {
			log.debug("It might not be suitable to run this in a transaction, since these operations can easily time out and there is no need for updates.");
		}
		final QueryCriteria queryCriteria = QueryCriteria
				.create()
				.add(Criteria.and(
						Criteria.eq(AuditLogEntry.FIELD_NODEID, this.nodes.get(this.currentNodeIndex)),
                                                Criteria.and(
                                                    Criteria.grt(AuditLogEntry.FIELD_SEQUENCENUMBER, sequenceStart), 
                                                    Criteria.and(Criteria.geq(AuditLogEntry.FIELD_TIMESTAMP, this.timestampFrom),
								Criteria.leq(AuditLogEntry.FIELD_TIMESTAMP, this.timestampTo)))))
								.add(Criteria.orderAsc(AuditLogEntry.FIELD_SEQUENCENUMBER));
		final List<AuditRecordData> rows;
		try {
                        /* clear the entity manager's cache to avoid an OOM
                         * due to an appearant memory leak bug in the Postgres
                         * JDBC driver.
                         */
                        this.entityManager.clear();
			rows = internalSelectAuditLogs(startPosition, maxResult, queryCriteria);
		} catch (DatabaseProtectionException eBatch) { // Will not continue in this method after the catch.
			if ( !firstTime ) {
				return 0;
			}
			final Long sequenceNumber;
			{
				final ProtectedData pd = eBatch.getEntity();
				if ( pd==null || !(pd instanceof AuditRecordData) ) {
					log.error("Stop testing current chunk since it seems to be to bad. A read object is not AuditRecordData");
					return maxResult;
				}
				sequenceNumber = ((AuditRecordData)pd).getSequenceNumber();
			}
			// Clear entity managers cache of managed beans. During the select of multiple records above the entityManager
			// cached results also after the failed records (that cased this exception caught here).
			// If we don't clear the entityManager here, when trying to select a non failing chunk below, we will get a cached result.
			// The cached results will contain null as "rowProtection", because one of the rows caused the exception.
			// NOTE NOTE: Never use entityManager.clear() inside JBoss, because it will clear caches for all threads killing performance.
			// here it can be used because this code is only used in the stand-alone CLI
			this.entityManager.clear();
			final int maxLengthToFailure = Math.max( (int)(sequenceNumber-sequenceNrSet.last()), 1 );
			{
				final StringWriter sw = new StringWriter();
                        try (PrintWriter pw = new PrintWriter(sw)) {
                            pw.print("Database integrity protection breach for row nodeId="+this.nodes.get(this.currentNodeIndex));
                            pw.println(" sequenceNumber="+ sequenceNumber);
                            pw.println("Reason was:");
                            pw.println( eBatch.getMessage() );
                            pw.println();
                        }
				this.auditLogValidationReport.error(new AuditLogReportElem(sequenceNumber, sequenceNumber, sw.toString()));
			}
			sequenceNrSet.add(sequenceNumber);
			if ( maxLengthToFailure>maxResult ) {
				log.error("Stop testing current chunk since it seems to be to bad. Object outside chunk received.");
				return maxResult;
			}
			for( int lengthToFailure=maxLengthToFailure; lengthToFailure+5>maxLengthToFailure&&lengthToFailure>0; lengthToFailure--) {
				if ( lengthToFailure==1 || read(startSequences.get(this.nodes.get(this.currentNodeIndex)) - 1, startPosition, lengthToFailure-1, false, sequenceNrSet)>0 ) {
					return lengthToFailure;
				}
			}
			log.error("Stop testing current chunk since it seems to be too bad. There are more errors than the ones that are logged.");
			return maxResult;
		}
		for ( final AuditRecordData auditRecordData : rows ) {
			if ( sequenceNrSet.add(auditRecordData.getSequenceNumber()) ) {
				continue;
			}
			final String msg = "Sequence number "+auditRecordData.getSequenceNumber()+" on node ID "+this.nodes.get(this.currentNodeIndex) + " occurred  more than once.";
			this.auditLogValidationReport.error(new AuditLogReportElem(auditRecordData.getSequenceNumber(), auditRecordData.getSequenceNumber(), msg));
		}
		return rows.size();
	}

	/**
	 * Select log entries using the supplied criteria.
	 * Optionally using startIndex and resultLimit (used if >0).
	 */
	@SuppressWarnings("unchecked")
	private List<AuditRecordData> internalSelectAuditLogs(final long startPosition, final int maxResult, final QueryCriteria criteria) {
		return buildConditionalQuery("SELECT a FROM AuditRecordData a", criteria, startPosition, maxResult).getResultList();
		//return buildConditionalQuery(entityManager, "SELECT DISTINCT a FROM AuditRecordData a left join fetch a.sequenceNumber", criteria, startIndex, max).getResultList();
	}

	/** @return a unique list of node identifiers that have been writing audit log to the database. */
	@SuppressWarnings("unchecked")
	public List<String> getNodeIds() {
		return this.entityManager.createQuery("SELECT DISTINCT a.nodeId FROM AuditRecordData a").getResultList();
	}

        /**
         * @return The last sequence number that was verified
         */
        public long getLastSeqNrFromPreviousChunk() {
            return lastSeqNrFromPreviousChunk;
        }

        /**
         * @return An read-only view of the map from all nodes that are considered to their start indexes
         */
        public Map<String, Long> getStartSequences() {
            return Collections.unmodifiableMap(startSequences);
        }        

	/**
	 * Build a JPA Query from the supplied queryStr and criteria.
	 * Optionally using startIndex and resultLimit (used if >0).
	 */
	private Query buildConditionalQuery(final String queryStr, final QueryCriteria criteria, final long startPosition, final int maxResult) {
		final Query query;
		if (criteria == null) {
			query = this.entityManager.createQuery(queryStr);
		} else {
			QueryGenerator generator = QueryGenerator.generator(AuditRecordData.class, criteria, "a");
			final String conditions = generator.generate();
			query = this.entityManager.createQuery(queryStr + conditions);
			for (final String key : generator.getParameterKeys()) {
				final Object param = generator.getParameterValue(key);
				query.setParameter(key, param);
			}
		}
		if (maxResult > 0) {
			query.setMaxResults(maxResult);
		}
		if (startPosition > -1) {
			query.setFirstResult((int)startPosition);// warn: startPosition will be negative if > 2^31 and then IllegalArgumentException will be thrown.
		}
		return query;
	}
}
