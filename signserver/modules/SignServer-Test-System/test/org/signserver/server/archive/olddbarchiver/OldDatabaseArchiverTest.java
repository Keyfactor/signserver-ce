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

import java.util.Random;
import org.apache.log4j.Logger;
import org.signserver.common.ArchiveDataVO;
import org.signserver.server.archive.ArchiveTest;
import org.signserver.server.archive.ArchiveTestCase;

/**
 * Tests for the OldDatabaseArchiver.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class OldDatabaseArchiverTest extends ArchiveTestCase {
    
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
    }

    /**
     * Tests that archiving with the default format (XML) works.
     * @throws Exception In case of error.
     */
    public void test10archiveTrueDefault() throws Exception {
        LOG.debug(">test10archiveTrueDefault");
        
        getWorkerSession().removeWorkerProperty(getSignerIdDummy1(), "ARCHIVERS");
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVE", "true");
        getWorkerSession().removeWorkerProperty(getSignerIdDummy1(), "ARCHIVER0.RESPONSETFORMAT");
        getWorkerSession().reloadConfiguration(getSignerIdDummy1());
        
        ArchiveDataVO archiveData = testArchive("<document id=\"" + random.nextLong() + "\"/>");
        assertEquals("default type of archive", ArchiveDataVO.TYPE_RESPONSE_XMLENCODED, archiveData.getType());
        
        LOG.debug("<test10archiveTrueDefault");
    }
    
    /**
     * Tests that archiving when specifying format XML works.
     * @throws Exception In case of error.
     */
    public void test20archiveTrueXML() throws Exception {
        LOG.debug(">test20archiveTrueXML");
        
        getWorkerSession().removeWorkerProperty(getSignerIdDummy1(), "ARCHIVERS");
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVE", "true");
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVER0.RESPONSEFORMAT", "XML");
        getWorkerSession().reloadConfiguration(getSignerIdDummy1());
        
        
        ArchiveDataVO archiveData = testArchive("<document id=\"" + random.nextLong() + "\"/>");
        assertEquals("type of archive", ArchiveDataVO.TYPE_RESPONSE_XMLENCODED, archiveData.getType());
        
        LOG.debug("<test20archiveTrueXML");
    }
    
    /**
     * Tests that archiving when specifying format BASE64 works.
     * @throws Exception In case of error.
     */
    public void test30archiveTrueBase64() throws Exception {
        LOG.debug(">test30archiveTrueBase64");
        
        getWorkerSession().removeWorkerProperty(getSignerIdDummy1(), "ARCHIVERS");
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVE", "true");
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVER0.RESPONSEFORMAT", "BASE64");
        getWorkerSession().reloadConfiguration(getSignerIdDummy1());
        
        
        ArchiveDataVO archiveData = testArchive("<document id=\"" + random.nextLong() + "\"/>");
        assertEquals("type of archive", ArchiveDataVO.TYPE_RESPONSE_BASE64ENCODED, archiveData.getType());
        
        LOG.debug("<test30archiveTrueBase64");
    }
    
    /**
     * Tests that archiving with the default format (XML) works also when 
     * archiver is specifying in ARCHIVERS property.
     * @throws Exception In case of error.
     */
    public void test40archiversDefault() throws Exception {
        LOG.debug(">test40archiversDefault");
        
        getWorkerSession().removeWorkerProperty(getSignerIdDummy1(), "ARCHIVE");
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVERS", "org.signserver.server.archive.olddbarchiver.OldDatabaseArchiver");
        getWorkerSession().removeWorkerProperty(getSignerIdDummy1(), "ARCHIVER0.RESPONSEFORMAT");
        getWorkerSession().reloadConfiguration(getSignerIdDummy1());
        
        
        ArchiveDataVO archiveData = testArchive("<document id=\"" + random.nextLong() + "\"/>");
        assertEquals("default type of archive", ArchiveDataVO.TYPE_RESPONSE_XMLENCODED, archiveData.getType());
        
        LOG.debug("<test40archiversDefault");
    }
    
    /**
     * Tests that archiving with format Base64 works also when 
     * archiver is specifying in ARCHIVERS property.
     * @throws Exception In case of error.
     */
    public void test50archiversBase64() throws Exception {
        LOG.debug(">test50archiversBase64");
        
        getWorkerSession().removeWorkerProperty(getSignerIdDummy1(), "ARCHIVE");
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVERS", "org.signserver.server.archive.olddbarchiver.OldDatabaseArchiver");
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), 
                "ARCHIVER0.RESPONSEFORMAT", "BASE64");
        getWorkerSession().reloadConfiguration(getSignerIdDummy1());
        
        
        ArchiveDataVO archiveData = testArchive("<document id=\"" + random.nextLong() + "\"/>");
        assertEquals("type of archive", ArchiveDataVO.TYPE_RESPONSE_BASE64ENCODED, archiveData.getType());
        
        LOG.debug("<test50archiversBase64");
    }
    
}
