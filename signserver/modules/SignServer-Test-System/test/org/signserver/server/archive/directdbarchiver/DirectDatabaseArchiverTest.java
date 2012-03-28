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
package org.signserver.server.archive.directdbarchiver;

import java.util.Arrays;
import java.util.Random;
import org.apache.log4j.Logger;
import org.signserver.common.*;
import org.signserver.server.archive.ArchiveTest;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.TestingSecurityManager;

/**
 * Tests the DirectDatabaseArchiver.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class DirectDatabaseArchiverTest extends ModulesTestCase {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ArchiveTest.class);

    private static Random random = new Random();
    
    @Override
    protected void setUp() throws Exception {
        super.setUp();
        SignServerUtil.installBCProvider();
        TestingSecurityManager.install();
        String signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull(signserverhome);
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
        TestingSecurityManager.remove();
    }	
	
    public void test00SetupDatabase() throws Exception {
        addSoftDummySigner(getSignerIdDummy1(), getSignerNameDummy1());
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVERS", "org.signserver.server.archive.directdbarchiver.DirectDatabaseArchiver");
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVER0.CONNECTIONNAME", "SignServerDS");
        getWorkerSession().removeWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVER0.ISDISABLED");
        getWorkerSession().reloadConfiguration(getSignerIdDummy1());
    }

    /**
     * Test signing with archiving enabled for a new document.
     * @throws Exception In case of error.
     */
    public void test01archiveNewDocument() throws Exception {
        LOG.debug(">test01OneArchiverCalled");
        
        testArchive("<document id=\"" + random.nextLong() + "\"/>");
        
        LOG.debug("<test01OneArchiverCalled");
    }
    
    /**
     * Test signing with archiving disabled.
     * @throws Exception In case of error.
     */
    public void test02isDisabled() throws Exception {
        LOG.debug(">test02isDisabled");
        
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVER0.ISDISABLED", "true");
        getWorkerSession().reloadConfiguration(getSignerIdDummy1());
        
        testNoArchive("<document id=\"" + random.nextLong() + "\"/>");
        
        LOG.debug("<test02archivingDisabled");
    }
    
    private void testArchive(final String document) throws Exception {
        // Process
        final GenericSignRequest signRequest =
                new GenericSignRequest(371, document.getBytes());
        GenericSignResponse response = (GenericSignResponse) 
                workerSession.process(getSignerIdDummy1(), signRequest, 
                new RequestContext());
        assertNotNull("no response", response);
        
        final String expectedArchiveId = response.getArchiveId();
        final ArchiveData expectedArchiveData = response.getArchiveData();
        
        ArchiveDataVO archiveData = getWorkerSession().findArchiveDataFromArchiveId(getSignerIdDummy1(), expectedArchiveId);
        assertEquals("same id in db", 
                expectedArchiveId, archiveData.getArchiveId());
        assertEquals("same signer id in db", 
                getSignerIdDummy1(), archiveData.getSignerId());
        
        assertTrue("same archived data", 
                Arrays.equals(expectedArchiveData.getData(), 
                archiveData.getArchivedBytes()));
    }
    
    private void testNoArchive(final String document) throws Exception {
        // Process
        final GenericSignRequest signRequest =
                new GenericSignRequest(371, document.getBytes());
        GenericSignResponse response = (GenericSignResponse) 
                workerSession.process(getSignerIdDummy1(), signRequest, 
                new RequestContext());
        assertNotNull("no response", response);
        
        final String expectedArchiveId = response.getArchiveId();
        
        ArchiveDataVO archiveData = getWorkerSession().findArchiveDataFromArchiveId(getSignerIdDummy1(), expectedArchiveId);
        
        assertNull("no archivedata in db", archiveData);
    }
    
    /**
     * Remove the workers created etc.
     * @throws Exception in case of error
     */
    public void test99TearDownDatabase() throws Exception {
        removeWorker(getSignerIdDummy1());
    }
}
