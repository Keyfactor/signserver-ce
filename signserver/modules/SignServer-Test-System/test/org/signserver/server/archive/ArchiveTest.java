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
import java.util.Random;
import org.apache.log4j.Logger;
import org.signserver.cli.CommonAdminInterface;
import org.signserver.common.ArchiveData;
import org.signserver.common.ArchiveDataVO;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerUtil;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.TestingSecurityManager;

/**
 * Tests for archiving.
 *
 * @author Markus Kilås
 * @version $Id$
 * 
 */
public class ArchiveTest extends ModulesTestCase {

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
                "ARCHIVE", "true");
        getWorkerSession().reloadConfiguration(getSignerIdDummy1());
    }

    /**
     * Test signing with archiving enabled for a new unique document.
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
    public void test03archivingNotSpecified() throws Exception {
        LOG.debug(">test03archivingNotSpecified");
        
        getWorkerSession().removeWorkerProperty(getSignerIdDummy1(), "ARCHIVE");
        getWorkerSession().reloadConfiguration(getSignerIdDummy1());
        
        testNoArchive("<document id=\"" + random.nextLong() + "\"/>");
        
        LOG.debug("<test03archivingNotSpecified");
    }
    
// This does not work because of bug DSS-408: Can not archive the same document twice    
//    /**
//     * Test signing with archiving enabled for the same document twice.
//     * @throws Exception In case of error.
//     */
//    public void test04archiveSameDocumentTwice() throws Exception {
//        LOG.debug(">test04archiveSameDocumentTwice");
//        
//        testArchive("<document/>");
//        testArchive("<document/>");
//        
//        LOG.debug("<test04archiveSameDocumentTwice");
//    }
    
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
                archiveData.getArchiveData().getData()));
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
