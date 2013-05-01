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
package org.signserver.server.archive.olddbarchiver;

import java.math.BigInteger;
import java.util.Collection;
import java.util.Random;
import org.apache.log4j.Logger;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.junit.After;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.common.ArchiveDataVO;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.RequestContext;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.ArchiveTest;
import org.signserver.server.archive.ArchiveTestCase;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests for the OldDatabaseArchiver.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class OldDatabaseArchiverTest extends ArchiveTestCase {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ArchiveTest.class);

    private static Random random = new Random();
    
    
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
    }	

    @Test
    public void test00SetupDatabase() throws Exception {
        addSoftDummySigner(getSignerIdDummy1(), getSignerNameDummy1());
        addSoftTimeStampSigner(getSignerIdTimeStampSigner1(), getSignerNameTimeStampSigner1());
    }

    /**
     * Tests that archiving with the default format (XML) works.
     * @throws Exception In case of error.
     */
    @Test
    public void test10archiveTrueDefault() throws Exception {
        LOG.debug(">test10archiveTrueDefault");
        
        getWorkerSession().removeWorkerProperty(getSignerIdDummy1(), "ARCHIVERS");
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVE", "true");
        getWorkerSession().reloadConfiguration(getSignerIdDummy1());
        
        ArchiveDataVO archiveData = testArchive("<document id=\"" + random.nextLong() + "\"/>");
        assertEquals("type of archive", ArchiveDataVO.TYPE_RESPONSE, archiveData.getType());
        
        LOG.debug("<test10archiveTrueDefault");
    }
    
    /**
     * Tests that archiving with the default format (XML) works also when 
     * archiver is specifying in ARCHIVERS property.
     * @throws Exception In case of error.
     */
    @Test
    public void test40archiversDefault() throws Exception {
        LOG.debug(">test40archiversDefault");
        
        getWorkerSession().removeWorkerProperty(getSignerIdDummy1(), "ARCHIVE");
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVERS", "org.signserver.server.archive.olddbarchiver.OldDatabaseArchiver");
        getWorkerSession().removeWorkerProperty(getSignerIdDummy1(), "ARCHIVER0.RESPONSEFORMAT");
        getWorkerSession().reloadConfiguration(getSignerIdDummy1());
        
        
        ArchiveDataVO archiveData = testArchive("<document id=\"" + random.nextLong() + "\"/>");
        assertEquals("type of archive", ArchiveDataVO.TYPE_RESPONSE, archiveData.getType());
        
        LOG.debug("<test40archiversDefault");
    }
    
    @Test
    public void test50archiveOnlyResponseIsDefault() throws Exception {
        LOG.debug(">test50archiveOnlyResponseIsDefault");
        
        final int signerId = getSignerIdTimeStampSigner1();
        
        // Setup archiving with no ARCHIVE_OF_TYPE (testing default value)
        getWorkerSession().removeWorkerProperty(signerId, "ARCHIVE");
        getWorkerSession().setWorkerProperty(signerId, 
                "ARCHIVERS", "org.signserver.server.archive.olddbarchiver.OldDatabaseArchiver");
        getWorkerSession().removeWorkerProperty(signerId, "ARCHIVER0.RESPONSEFORMAT");
        getWorkerSession().removeWorkerProperty(signerId, "ARCHIVER0.ARCHIVE_OF_TYPE");
        getWorkerSession().reloadConfiguration(signerId);
        archiveOnlyResponse(signerId);
        
        LOG.debug("<test50archiveOnlyResponseIsDefault");
    }

    @Test
    public void test50archiveOnlyResponse() throws Exception {
        LOG.debug(">test50archiveOnlyResponse");
        
        final int signerId = getSignerIdTimeStampSigner1();
        
        // Setup archiving with ARCHIVE_OF_TYPE=RESPONSE (testing explicit value)
        getWorkerSession().removeWorkerProperty(signerId, "ARCHIVE");
        getWorkerSession().setWorkerProperty(signerId, 
                "ARCHIVERS", "org.signserver.server.archive.olddbarchiver.OldDatabaseArchiver");
        getWorkerSession().removeWorkerProperty(signerId, "ARCHIVER0.RESPONSEFORMAT");
        getWorkerSession().setWorkerProperty(signerId, "ARCHIVER0.ARCHIVE_OF_TYPE", "RESPONSE");
        getWorkerSession().reloadConfiguration(signerId);
        archiveOnlyResponse(signerId);
        
        LOG.debug("<test50archiveOnlyResponse");
    }

    @Test
    public void test50archiveOnlyRequest() throws Exception {
        LOG.debug(">test50archiveOnlyRequest");
        
        final int signerId = getSignerIdTimeStampSigner1();
        
        // Setup archiving with ARCHIVE_OF_TYPE=REQUEST
        getWorkerSession().removeWorkerProperty(signerId, "ARCHIVE");
        getWorkerSession().setWorkerProperty(signerId, 
                "ARCHIVERS", "org.signserver.server.archive.olddbarchiver.OldDatabaseArchiver");
        getWorkerSession().removeWorkerProperty(signerId, "ARCHIVER0.RESPONSEFORMAT");
        getWorkerSession().setWorkerProperty(signerId, "ARCHIVER0.ARCHIVE_OF_TYPE", "REQUEST");
        getWorkerSession().reloadConfiguration(signerId);
        archiveOnlyRequest(signerId);
        
        LOG.debug("<test50archiveOnlyRequest");
    }

    @Test
    public void test50archiveRequestAndResponse() throws Exception {
        LOG.debug(">test50archiveRequestAndResponse");
        
        // Setup archiving
        final int signerId = getSignerIdTimeStampSigner1();
        getWorkerSession().removeWorkerProperty(signerId, "ARCHIVE");
        getWorkerSession().setWorkerProperty(signerId, 
                "ARCHIVERS", "org.signserver.server.archive.olddbarchiver.OldDatabaseArchiver");
        getWorkerSession().removeWorkerProperty(signerId, "ARCHIVER0.RESPONSEFORMAT");
        getWorkerSession().setWorkerProperty(signerId, "ARCHIVER0.ARCHIVE_OF_TYPE", "REQUEST_AND_RESPONSE");
        getWorkerSession().reloadConfiguration(signerId);
        
        archiveRequestAndResponse(signerId);
        
        LOG.debug("<test50archiveRequestAndResponse");
    }

    /**
     * Test that the archiver is using the X-Forwarded-For header when the property is set.
     * 
     * @throws Exception
     */
    @Test
    public void test60archiveWithXForwardedFor() throws Exception {
        LOG.debug(">test60archiveWithXForwardedFor");
        
        final int signerId = getSignerIdDummy1();
        
        getWorkerSession().setWorkerProperty(signerId, "ARCHIVERS", 
                "org.signserver.server.archive.olddbarchiver.OldDatabaseArchiver");
        getWorkerSession().setWorkerProperty(signerId, "ARCHIVER0.USE_FORWARDED_ADDRESS", "true");
        getWorkerSession().reloadConfiguration(signerId);
        
        ArchiveDataVO archiveData = testArchive("<document id=\"" + random.nextLong() + "\"/>",
                "1.2.3.4", "42.42.42.42");
        
        final String ip = archiveData.getRequestIP();
        
        assertEquals("Archiver should use X-Forwarded-For IP address", "42.42.42.42", ip);
        
        LOG.debug("<test60archiveWithXForwardedFor");
    }
    
    /**
     * Test that the archiver is not using the X-Forwarded-For header when property is not set.
     * 
     * @throws Exception
     */
    @Test
    public void test60archiveWithXForwardedForNotUsed() throws Exception {
        LOG.debug(">test60archiveWithXForwardedForNotUsed");
        
        final int signerId = getSignerIdDummy1();
        
        getWorkerSession().setWorkerProperty(signerId, "ARCHIVERS", 
                "org.signserver.server.archive.olddbarchiver.OldDatabaseArchiver");
        getWorkerSession().removeWorkerProperty(signerId, "ARCHIVER0.USE_FORWARDED_ADDRESS");
        getWorkerSession().reloadConfiguration(signerId);
        
        ArchiveDataVO archiveData = testArchive("<document id=\"" + random.nextLong() + "\"/>",
                "1.2.3.4", "42.42.42.42");
        
        final String ip = archiveData.getRequestIP();
        
        assertEquals("Archiver should not use X-Forwarded-For IP address", "1.2.3.4", ip);
        
        LOG.debug("<test60archiveWithXForwardedForNotUsed");
    }
    
    /**
     * Test that the archiver is not using the X-Forwaded-For header when the property is set
     * and has the value "false". 
     *
     * @throws Exception
     */
    @Test
    public void test60archiveWithXForwardedForFalse() throws Exception {
        LOG.debug(">test60archiveWithXForwardedForFalse");
        
        final int signerId = getSignerIdDummy1();
        
        getWorkerSession().setWorkerProperty(signerId, "ARCHIVERS", 
                "org.signserver.server.archive.olddbarchiver.OldDatabaseArchiver");
        getWorkerSession().setWorkerProperty(signerId, "ARCHIVER0.USE_FORWARDED_ADDRESS", "false");
        getWorkerSession().reloadConfiguration(signerId);
        
        ArchiveDataVO archiveData = testArchive("<document id=\"" + random.nextLong() + "\"/>",
                "1.2.3.4", "42.42.42.42");
        
        final String ip = archiveData.getRequestIP();
        
        assertEquals("Archiver should not use X-Forwarded-For IP address", "1.2.3.4", ip);
        
        LOG.debug("<test60archiveWithXForwardedForFalse");
    }
    
    /**
     * Test setting the USE_X_FORDED_FOR property, but not including the header, to ensure the standard request IP is used as a fallback
     *
     * @throws Exception
     */
    @Test
    public void test60archiveWithXForwardedWithoutHeader() throws Exception {
        LOG.debug(">test60archiveWithXForwardedForWithoutHeader");
        
        final int signerId = getSignerIdDummy1();
        
        getWorkerSession().setWorkerProperty(signerId, "ARCHIVERS", 
                "org.signserver.server.archive.olddbarchiver.OldDatabaseArchiver");
        getWorkerSession().setWorkerProperty(signerId, "ARCHIVER0.USE_FORWARDED_ADDRESS", "true");
        getWorkerSession().reloadConfiguration(signerId);
        
        ArchiveDataVO archiveData = testArchive("<document id=\"" + random.nextLong() + "\"/>",
                "1.2.3.4", null);
        
        final String ip = archiveData.getRequestIP();
        
        assertEquals("Archiver should use the request IP address", "1.2.3.4", ip);
        
        LOG.debug("<test60archiveWithXForwardedForWithoutHeader");
    }
    
    protected Collection<? extends Archivable> archiveTimeStamp(int signerId) throws Exception {
        // Process
        int reqid = random.nextInt();

        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        byte[] requestBytes = timeStampRequest.getEncoded();

        GenericSignRequest signRequest =
                new GenericSignRequest(reqid, requestBytes);

        final GenericSignResponse response = (GenericSignResponse) workerSession.process(
                signerId, signRequest, new RequestContext());
        assertNotNull("no response", response);
        
        return response.getArchivables();
    }
 
    /**
     * Remove the workers created etc.
     * @throws Exception in case of error
     */
    @Test
    public void test99TearDownDatabase() throws Exception {
        removeWorker(getSignerIdDummy1());
        removeWorker(getSignerIdTimeStampSigner1());
    }
}
