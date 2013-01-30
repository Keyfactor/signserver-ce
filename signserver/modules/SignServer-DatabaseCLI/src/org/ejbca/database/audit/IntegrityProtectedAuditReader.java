/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.database.audit;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;
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
import org.cesecore.dbprotection.DatabaseProtectionError;
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

	/**
	 * Creates a new instance of this reader that can be used to fetch verified audit log data.
	 * @param entityManager
	 * @param timestampFrom
	 * @param timestampTo
	 * @param maxFetchSize
	 */
	public IntegrityProtectedAuditReader(final EntityManager entityManager, long timestampFrom, long timestampTo, int maxFetchSize) {
		this.entityManager = entityManager;
		this.timestampFrom = timestampFrom;
		this.timestampTo = timestampTo;
		this.maxFetchSize = maxFetchSize;
		// We fetch all the nodes, even if there are no events for a node in this time-span
		this.nodes = getNodeIds();
		// Make sure that we really do verify and throw detectable DatabaseProtectionError if the verification fails.
		ConfigurationHolder.instance();
		ConfigurationHolder.updateConfiguration("databaseprotection.enableverify.AuditRecordData", "true");
		ConfigurationHolder.updateConfiguration("databaseprotection.erroronverifyfail", "true");
	}

	public boolean isDone() {
		return this.nodes.size()<=this.currentNodeIndex;
	}

	/** @return the audit log validation report after all the data has been fetched and verified. */
	public AuditLogValidationReport getAuditLogValidationReport() {
		return this.auditLogValidationReport;
	}

	public int getNodeId() {
		return this.currentNodeIndex;
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
		final SortedSet<Long> sequenceNrSet = new ConcurrentSkipListSet<Long>();
		sequenceNrSet.add( Long.valueOf(this.lastSeqNrFromPreviousChunk) );
		final int nrRead = read(this.startIndex, this.maxFetchSize, true, sequenceNrSet);
		if ( nrRead<1 ) {// nothing more to read from this node
			this.startIndex = 0;
			this.currentNodeIndex++;
			this.lastSeqNrFromPreviousChunk = -1;
			return getNextVerifiedChunk();
		}
		this.lastSeqNrFromPreviousChunk = checkForMissingSequenceNrs(sequenceNrSet);
		this.startIndex += nrRead;
		return nrRead;
	}
	private long checkForMissingSequenceNrs(final SortedSet<Long> sequenceNrSet) {
		final long highestNr = sequenceNrSet.last().longValue();
		final long lowestNr = sequenceNrSet.first().longValue();
		if ( highestNr+1==lowestNr+sequenceNrSet.size() ) {
			sequenceNrSet.clear();// all sequence number must exist if this size.
			return highestNr;// done
		}
		// some rows must be missing. find out which
		long currLowNr = lowestNr;
		while ( true ) {
			sequenceNrSet.remove(Long.valueOf(currLowNr));
			if ( sequenceNrSet.isEmpty() ) {
				break; // no more rows
			}
			final long nextLowestNr = sequenceNrSet.first().longValue();
			if ( currLowNr+1!=nextLowestNr ) {
				final String msg = "Database integrity protection breach for row nodeId="+this.nodes.get(this.currentNodeIndex)
						+ " lastVerifiedSequenceNumber="+currLowNr + " thisSequenceNumber="+nextLowestNr;
				//log.warn(msg);
				this.auditLogValidationReport.error(new AuditLogReportElem(Long.valueOf(currLowNr), Long.valueOf(nextLowestNr), msg));
			}
			currLowNr = nextLowestNr;
		}
		return highestNr;
	}
	private int read(final long startPosition, final int maxResult, final boolean firstTime, final SortedSet<Long> sequenceNrSet) {
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
						Criteria.and(Criteria.geq(AuditLogEntry.FIELD_TIMESTAMP, Long.valueOf(this.timestampFrom)),
								Criteria.leq(AuditLogEntry.FIELD_TIMESTAMP, Long.valueOf(this.timestampTo)))))
								.add(Criteria.orderAsc(AuditLogEntry.FIELD_SEQUENCENUMBER));
		final List<AuditRecordData> rows;
		try {
			rows = internalSelectAuditLogs(startPosition, maxResult, queryCriteria);
		} catch (DatabaseProtectionError eBatch) { // Will not continue in this method after the catch.
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
			final int maxLengthToFailure = Math.max( (int)(sequenceNumber.longValue()-sequenceNrSet.last().longValue()), 1 );
			{
				final StringWriter sw = new StringWriter();
				final PrintWriter pw = new PrintWriter(sw);
				pw.print("Database integrity protection breach for row nodeId="+this.nodes.get(this.currentNodeIndex));
				pw.println(" sequenceNumber="+ sequenceNumber);
				pw.println("Reason was:");
				pw.println( eBatch.getMessage() );
				pw.println();
				pw.close();
				this.auditLogValidationReport.error(new AuditLogReportElem(sequenceNumber, sequenceNumber, sw.toString()));
			}
			sequenceNrSet.add(sequenceNumber);
			if ( maxLengthToFailure>maxResult ) {
				log.error("Stop testing current chunk since it seems to be to bad. Object outside chunk received.");
				return maxResult;
			}
			for( int lengthToFailure=maxLengthToFailure; lengthToFailure+5>maxLengthToFailure&&lengthToFailure>0; lengthToFailure--) {
				if ( lengthToFailure==1 || read(startPosition, lengthToFailure-1, false, sequenceNrSet)>0 ) {
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
			final String msg = "Sequence number "+auditRecordData.getSequenceNumber()+" on node id "+this.nodes.get(this.currentNodeIndex) + " occurred  more than once.";
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
	private List<String> getNodeIds() {
		return this.entityManager.createQuery("SELECT DISTINCT a.nodeId FROM AuditRecordData a").getResultList();
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
