/*************************************************************************
 *                                                                       *
 *  SignServer: The OpenSource Automated Signing Server                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.server.archive;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Random;
import org.apache.log4j.Logger;
import org.cesecore.util.query.QueryCriteria;
import org.cesecore.util.query.elems.RelationalOperator;
import org.cesecore.util.query.elems.Term;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import static org.junit.Assert.*;
import org.junit.Test;
import org.signserver.common.ArchiveMetadata;

/**
 * Tests for archiving.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ArchiveTest extends ArchiveTestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ArchiveTest.class);

    private static Random random = new Random();
    	
    @Test
    public void test00SetupDatabase() throws Exception {
        addSoftDummySigner(getSignerIdDummy1(), getSignerNameDummy1());
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVE", "true");
        getWorkerSession().reloadConfiguration(getSignerIdDummy1());
    }

    /**
     * Test signing with archiving enabled for a new unique document.
     * @throws Exception In case of error.
     */
    @Test
    public void test01archiveNewDocument() throws Exception {
        LOG.debug(">test01OneArchiverCalled");
        
        testArchive("<document id=\"" + random.nextLong() + "\"/>");
        
        LOG.debug("<test01OneArchiverCalled");
    }
    
    /**
     * Test signing with archiving disabled.
     * @throws Exception In case of error.
     */
    @Test
    public void test02archivingDisabled() throws Exception {
        LOG.debug(">test02archivingDisabled");
        
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVE", "false");
        getWorkerSession().reloadConfiguration(getSignerIdDummy1());
        
        testNoArchive("<document id=\"" + random.nextLong() + "\"/>");
        
        LOG.debug("<test02archivingDisabled");
    }
    
    /**
     * Test signing without archiving properties.
     * @throws Exception In case of error.
     */
    @Test
    public void test03archivingNotSpecified() throws Exception {
        LOG.debug(">test03archivingNotSpecified");
        
        getWorkerSession().removeWorkerProperty(getSignerIdDummy1(), "ARCHIVE");
        getWorkerSession().reloadConfiguration(getSignerIdDummy1());
        
        testNoArchive("<document id=\"" + random.nextLong() + "\"/>");
        
        LOG.debug("<test03archivingNotSpecified");
    }
    
    /**
     * Test signing with archiving enabled for the same document twice.
     * @throws Exception In case of error.
     */
    @Test
    public void test04archiveSameDocumentTwice() throws Exception {
        LOG.debug(">test04archiveSameDocumentTwice");
        
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), "ARCHIVE", "TRUE");
        getWorkerSession().reloadConfiguration(getSignerIdDummy1());
        
        testArchive("<document/>");
        testArchive("<document/>");
        
        LOG.debug("<test04archiveSameDocumentTwice");
    }
    
    @Test
    public void test05archiveTestQuery() throws Exception {
        LOG.debug(">test05archiveTestQuery");
        
        final String document = "<document/>";
        
        // enable archiving
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), "ARCHIVE", "TRUE");
        getWorkerSession().reloadConfiguration(getSignerIdDummy1());
        
        // make sure timestamps don't "collide" with earlier tests
        Thread.sleep(10);
        // record timestamp before doing requests
        final long timestamp = System.currentTimeMillis();
        
        testArchive(document);
        
        // test querying archive
        final QueryCriteria qc = QueryCriteria.create();
        
        qc.add(new Term(RelationalOperator.GE, ArchiveMetadata.TIME, Long.valueOf(timestamp)));
        
        Collection<ArchiveMetadata> metadatas =
                getWorkerSession().searchArchive(0, 10, qc, false);
        
        assertEquals("Number of archive entries", 1, metadatas.size());
        assertNull("Should not include archive data",
                metadatas.iterator().next().getArchiveData());
    
        
        final ArchiveMetadata metadata = metadatas.iterator().next();
        final String uniqueId = metadata.getUniqueId();
        final List<String> uniqueIds = Arrays.asList(uniqueId);
        
        // test querying on a uniqueId from an earlier archiving
        Collection<ArchiveMetadata> fetchedMetadatas =
                getWorkerSession().searchArchiveWithIds(uniqueIds, true);
        assertEquals("Number of fetched items", 1, fetchedMetadatas.size());
        assertNotNull("Response data returned",
                fetchedMetadatas.iterator().next().getArchiveData());
        assertEquals("UniqueId matching", uniqueId,
                fetchedMetadatas.iterator().next().getUniqueId());
        
        // test querying on uniqueId not including archiveData
        fetchedMetadatas =
                getWorkerSession().searchArchiveWithIds(uniqueIds, false);
        assertEquals("Number of fetched items", 1, fetchedMetadatas.size());
        assertNull("Archive data not included",
                fetchedMetadatas.iterator().next().getArchiveData());
        assertEquals("UniqueId matching", uniqueId,
                fetchedMetadatas.iterator().next().getUniqueId());
        
        // test that trying to fetch an unexisting ID doesn't return any hits
        fetchedMetadatas =
                getWorkerSession().searchArchiveWithIds(Arrays.asList("dummyUniqueId"),
                                                        true);
        assertEquals("Should get empty result", 0, fetchedMetadatas.size());

        // do criteria-based query, including archive data
        metadatas = getWorkerSession().searchArchive(0, 10, qc, true);
        assertNotNull("Should include archive data",
                metadatas.iterator().next().getArchiveData());
    }   
    
    /**
     * Remove the workers created etc.
     * @throws Exception in case of error
     */
    @Test
    public void test99TearDownDatabase() throws Exception {
        removeWorker(getSignerIdDummy1());
    }

}
