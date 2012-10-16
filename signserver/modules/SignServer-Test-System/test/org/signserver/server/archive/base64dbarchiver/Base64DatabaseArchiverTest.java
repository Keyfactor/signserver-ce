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
package org.signserver.server.archive.base64dbarchiver;

import java.math.BigInteger;
import java.util.Collection;
import java.util.Random;
import org.apache.log4j.Logger;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.signserver.common.ArchiveDataVO;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.RequestContext;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.ArchiveTest;
import org.signserver.server.archive.ArchiveTestCase;

/**
 * Tests for the OldDatabaseArchiver.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class Base64DatabaseArchiverTest extends ArchiveTestCase {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ArchiveTest.class);

    private static Random random = new Random();
    
    
    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }	
	
    public void test00SetupDatabase() throws Exception {
        addSoftDummySigner(getSignerIdDummy1(), getSignerNameDummy1());
        addSoftTimeStampSigner(getSignerIdTimeStampSigner1(), getSignerNameTimeStampSigner1());
    }
        
    /**
     * Tests archiving with the base64 database archiver.
     * @throws Exception In case of error.
     */
    public void test30archiveBase64() throws Exception {
        LOG.debug(">test30archiveTrueBase64");
        
        getWorkerSession().removeWorkerProperty(getSignerIdDummy1(), "ARCHIVERS");
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVERS", "org.signserver.server.archive.base64dbarchiver.Base64DatabaseArchiver");
        getWorkerSession().reloadConfiguration(getSignerIdDummy1());
        
        ArchiveDataVO archiveData = testArchive("<document id=\"" + random.nextLong() + "\"/>");
        assertEquals("type of archive", ArchiveDataVO.TYPE_RESPONSE, archiveData.getType());
        
        LOG.debug("<test30archiveTrueBase64");
    }
    
    public void test50archiveOnlyResponseIsDefault() throws Exception {
        LOG.debug(">test50archiveOnlyResponseIsDefault");
        
        final int signerId = getSignerIdTimeStampSigner1();
        
        // Setup archiving with no ARCHIVE_OF_TYPE (testing default value)
        getWorkerSession().removeWorkerProperty(signerId, "ARCHIVE");
        getWorkerSession().setWorkerProperty(signerId, 
                "ARCHIVERS", "org.signserver.server.archive.base64dbarchiver.Base64DatabaseArchiver");
        getWorkerSession().removeWorkerProperty(signerId, "ARCHIVER0.RESPONSEFORMAT");
        getWorkerSession().removeWorkerProperty(signerId, "ARCHIVER0.ARCHIVE_OF_TYPE");
        getWorkerSession().reloadConfiguration(signerId);
        archiveOnlyResponse(signerId);
        
        LOG.debug("<test50archiveOnlyResponseIsDefault");
    }
    
    public void test50archiveOnlyResponse() throws Exception {
        LOG.debug(">test50archiveOnlyResponse");
        
        final int signerId = getSignerIdTimeStampSigner1();
        
        // Setup archiving with ARCHIVE_OF_TYPE=RESPONSE (testing explicit value)
        getWorkerSession().removeWorkerProperty(signerId, "ARCHIVE");
        getWorkerSession().setWorkerProperty(signerId, 
                "ARCHIVERS", "org.signserver.server.archive.base64dbarchiver.Base64DatabaseArchiver");
        getWorkerSession().removeWorkerProperty(signerId, "ARCHIVER0.RESPONSEFORMAT");
        getWorkerSession().setWorkerProperty(signerId, "ARCHIVER0.ARCHIVE_OF_TYPE", "RESPONSE");
        getWorkerSession().reloadConfiguration(signerId);
        archiveOnlyResponse(signerId);
        
        LOG.debug("<test50archiveOnlyResponse");
    }
    
    public void test50archiveOnlyRequest() throws Exception {
        LOG.debug(">test50archiveOnlyRequest");
        
        final int signerId = getSignerIdTimeStampSigner1();
        
        // Setup archiving with ARCHIVE_OF_TYPE=REQUEST
        getWorkerSession().removeWorkerProperty(signerId, "ARCHIVE");
        getWorkerSession().setWorkerProperty(signerId, 
                "ARCHIVERS", "org.signserver.server.archive.base64dbarchiver.Base64DatabaseArchiver");
        getWorkerSession().removeWorkerProperty(signerId, "ARCHIVER0.RESPONSEFORMAT");
        getWorkerSession().setWorkerProperty(signerId, "ARCHIVER0.ARCHIVE_OF_TYPE", "REQUEST");
        getWorkerSession().reloadConfiguration(signerId);
        archiveOnlyRequest(signerId);
        
        LOG.debug("<test50archiveOnlyRequest");
    }
    
    public void test50archiveRequestAndResponse() throws Exception {
        LOG.debug(">test50archiveRequestAndResponse");
        
        // Setup archiving
        final int signerId = getSignerIdTimeStampSigner1();
        getWorkerSession().removeWorkerProperty(signerId, "ARCHIVE");
        getWorkerSession().setWorkerProperty(signerId, 
                "ARCHIVERS", "org.signserver.server.archive.base64dbarchiver.Base64DatabaseArchiver");
        getWorkerSession().removeWorkerProperty(signerId, "ARCHIVER0.RESPONSEFORMAT");
        getWorkerSession().setWorkerProperty(signerId, "ARCHIVER0.ARCHIVE_OF_TYPE", "REQUEST_AND_RESPONSE");
        getWorkerSession().reloadConfiguration(signerId);
        
        archiveRequestAndResponse(signerId);
        
        LOG.debug("<test50archiveRequestAndResponse");
    }
 
    /**
     * Remove the workers created etc.
     * @throws Exception in case of error
     */
    public void test99TearDownDatabase() throws Exception {
        removeWorker(getSignerIdDummy1());
    }
}
