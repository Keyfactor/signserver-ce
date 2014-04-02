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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.SignServerUtil;
import org.signserver.server.archive.test1archiver.Test1Archiver;
import static org.signserver.server.archive.test1archiver.Test1Archiver.*;
import org.signserver.server.archive.test1archiver.Test1Signer;
import org.signserver.server.archive.test1archiver.Test2Archiver;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.TestingSecurityManager;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests for the Archiving API.
 *
 * @author Markus Kilås
 * @version $Id$
 * 
 * @see Test1Archiver
 * @see Test2Archiver
 * @see Test1Signer
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ArchiveAPITest extends ModulesTestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ArchiveAPITest.class);

    private File archiver0File;
    private File archiver1File;
    private File archiver2File;
    
    @Before
    @Override
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
        TestingSecurityManager.install();
        String signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull(signserverhome);
        File tmp = new File(signserverhome, "tmp");
        archiver0File = new File(tmp, "archiver0.out");
        archiver1File = new File(tmp, "archiver1.out");
        archiver2File = new File(tmp, "archiver2.out");
        
        if (archiver0File.exists()) {
            assertTrue("delete archiver 0 file", archiver0File.delete());
        }
        if (archiver1File.exists()) {
            assertTrue("delete archiver 1 file", archiver1File.delete());
        }
        if (archiver2File.exists()) {
            assertTrue("delete archiver 2 file", archiver2File.delete());
        }
    }

    @After
    @Override
    public void tearDown() throws Exception {
        TestingSecurityManager.remove();
    }	

    @Test
    public void test00SetupDatabase() throws Exception {
        addSigner(Test1Signer.class.getName());
    }

    /**
     * Test with one configured Archiver.
     * 
     * @throws Exception In case of error.
     */
    @Test
    public void test01OneArchiverCalled() throws Exception {
        LOG.debug(">test01OneArchiverCalled");

        // Setup archiver: 0
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVERS", Test1Archiver.class.getName());
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVER0.FILE", archiver0File.getAbsolutePath());
        
        // Reload
        getWorkerSession().reloadConfiguration(getSignerIdDummy1());
        
        // Process
        signSomething();
      
        // Get result
        final Properties archive0 = readArchive(archiver0File);
        
        // Test called
        assertNotNull("archiver0 run", archive0.getProperty(PROCESSED));
        
        // Test workerid
        assertEquals("worker id", String.valueOf(getSignerIdDummy1()), 
                archive0.getProperty(WORKERID));
        
        // Test init with right slotListIndex
        assertEquals("listIndex 0", "0", archive0.getProperty(LISTINDEX));
        
        // Test right class
        assertEquals("class for 0", Test1Archiver.class.getName(), 
                archive0.getProperty(CLASSNAME));
        
        // Test that EntityManager is available
        assertTrue("em available", Boolean.parseBoolean(archive0.getProperty(ENTITYMANAGER_AVAILABLE)));

        LOG.debug("<test01OneArchiverCalled");
    }
    
    /**
     * Test with three configured ArchiverS.
     * 
     * @throws Exception In case of error.
     */
    @Test
    public void test02ThreeArchiversCalled() throws Exception {
        LOG.debug(">test02ThreeArchiversCalled");

        // Setup archiver: 0, 1 and 2
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVERS", Test1Archiver.class.getName() 
                + "," + Test1Archiver.class.getName()
                + "," + Test2Archiver.class.getName());
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVER0.FILE", archiver0File.getAbsolutePath());
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVER1.FILE", archiver1File.getAbsolutePath());
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVER2.FILE", archiver2File.getAbsolutePath());
        
        // Reload
        getWorkerSession().reloadConfiguration(getSignerIdDummy1());
        
        // Process
        signSomething();
      
        // Get result
        final Properties archive0 = readArchive(archiver0File);
        final Properties archive1 = readArchive(archiver1File);
        final Properties archive2 = readArchive(archiver2File);
        
        // Test called
        assertNotNull("archiver0 run", archive0.getProperty(PROCESSED));
        assertNotNull("archiver1 run", archive1.getProperty(PROCESSED));
        assertNotNull("archiver2 run", archive2.getProperty(PROCESSED));
        
        // Test workerid
        assertEquals("worker id", String.valueOf(getSignerIdDummy1()), 
                archive0.getProperty(WORKERID));
        assertEquals("worker id", String.valueOf(getSignerIdDummy1()), 
                archive1.getProperty(WORKERID));
        assertEquals("worker id", String.valueOf(getSignerIdDummy1()), 
                archive2.getProperty(WORKERID));
        
        // Test init with right slotListIndex
        assertEquals("listIndex 0", "0", archive0.getProperty(LISTINDEX));
        assertEquals("listIndex 1", "1", archive1.getProperty(LISTINDEX));
        assertEquals("listIndex 2", "2", archive2.getProperty(LISTINDEX));

        // Test right class
        assertEquals("class for 0", Test1Archiver.class.getName(), 
                archive0.getProperty(CLASSNAME));
        assertEquals("class for 1", Test1Archiver.class.getName(), 
                archive1.getProperty(CLASSNAME));
        assertEquals("class for 2", Test2Archiver.class.getName(), 
                archive2.getProperty(CLASSNAME));
        
        // Test that each archiver has its own instance
        assertTrue("a0 != a1", 
                !archive0.getProperty(INSTANCE).equals(archive1.getProperty(INSTANCE)));
        assertTrue("a1 != a2", 
                !archive1.getProperty(INSTANCE).equals(archive2.getProperty(INSTANCE)));
        
        LOG.debug("<test02ThreeArchiversCalled");
    }
    
    /**
     * Tests that nothings breaks when an Archiver chooses to not archive an
     * Archivable (for instance because it does not handle that type).
     * 
     * @throws Exception In case of error.
     */
    @Test
    public void test03archiverNotArchiving() throws Exception {
        LOG.debug(">test03archiverNotArchiving");

        // Setup archiver: 0, 1 and 2
        // where archiver 0 does not archive anything
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVERS", Test1Archiver.class.getName() 
                + "," + Test1Archiver.class.getName()
                + "," + Test2Archiver.class.getName());
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVER0.FILE", archiver0File.getAbsolutePath());
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVER1.FILE", archiver1File.getAbsolutePath());
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVER2.FILE", archiver2File.getAbsolutePath());
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVER0.ISDISABLED", "true");
        
        // Reload
        getWorkerSession().reloadConfiguration(getSignerIdDummy1());
        
        // Process
        signSomething();
      
        // Get result: Now archive0 should not exist but the other should
        assertFalse("no archive for archiver 0", archiver0File.exists());
        final Properties archive1 = readArchive(archiver1File);
        final Properties archive2 = readArchive(archiver2File);
        
        // Test called
        assertNotNull("archiver1 run", archive1.getProperty(PROCESSED));
        assertNotNull("archiver2 run", archive2.getProperty(PROCESSED));
        
        // Test workerid
        assertEquals("worker id", String.valueOf(getSignerIdDummy1()), 
                archive1.getProperty(WORKERID));
        assertEquals("worker id", String.valueOf(getSignerIdDummy1()), 
                archive2.getProperty(WORKERID));
        
        // Test init with right slotListIndex
        assertEquals("listIndex 1", "1", archive1.getProperty(LISTINDEX));
        assertEquals("listIndex 2", "2", archive2.getProperty(LISTINDEX));

        // Test right class
        assertEquals("class for 1", Test1Archiver.class.getName(), 
                archive1.getProperty(CLASSNAME));
        assertEquals("class for 2", Test2Archiver.class.getName(), 
                archive2.getProperty(CLASSNAME));
        
        // Test that each archiver has its own instance
        assertTrue("a1 != a2", 
                !archive1.getProperty(INSTANCE).equals(archive2.getProperty(INSTANCE)));
        
        LOG.debug("<test03archiverNotArchiving");
    }
    
    /**
     * Tests that when an Archiver fails to Archive the request fails with 
     * an exception.
     * 
     * @throws Exception In case of error.
     */
    @Test
    public void test04archiverFailsToArchive() throws Exception {
        LOG.debug(">test04archiverFailsToArchive");

        // Setup archiver: 0, 1 and 2
        // where archiver 1 will fail
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVERS", Test1Archiver.class.getName() 
                + "," + Test1Archiver.class.getName()
                + "," + Test2Archiver.class.getName());
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVER0.FILE", archiver0File.getAbsolutePath());
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVER1.FILE", archiver1File.getAbsolutePath());
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVER2.FILE", archiver2File.getAbsolutePath());
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVER1.DOFAIL", "true");
        
        // Reload
        getWorkerSession().reloadConfiguration(getSignerIdDummy1());
        
        // Process
        try {
            signSomething();
            fail("Archiving should have failed");
        } catch (SignServerException ignored) {
            // OK
        }
        
        LOG.debug("<test04archiverFailsToArchive");
    }
    
    /**
     * Remove the workers created etc.
     * @throws Exception in case of error
     */
    @Test
    public void test99TearDownDatabase() throws Exception {
        removeWorker(getSignerIdDummy1());
    }
    
    private static Properties readArchive(File archiveFile) throws IOException {
        final Properties result = new Properties();
        InputStream in = null;
        try {
            in = new FileInputStream(archiveFile);
            result.load(in);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ignored) {} // NOPMD
            }
        }
        return result;
    }

    private void signSomething() throws Exception {
        final String testDocument = "<document/>";
        final GenericSignRequest signRequest =
                new GenericSignRequest(371, testDocument.getBytes());
        workerSession.process(getSignerIdDummy1(),  signRequest, 
                new RequestContext());
    }
}
