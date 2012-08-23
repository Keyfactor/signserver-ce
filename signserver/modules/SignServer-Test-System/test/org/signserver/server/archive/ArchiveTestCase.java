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
import org.signserver.common.*;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.TestingSecurityManager;

/**
 * Re-usable test case for archiving.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ArchiveTestCase extends ModulesTestCase {
    
    
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
    
    protected ArchiveDataVO testArchive(final String document) throws Exception {
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
        return archiveData;
    }
    
    protected void testNoArchive(final String document) throws Exception {
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

}
