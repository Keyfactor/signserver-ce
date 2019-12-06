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
package org.signserver.admin.web;

import java.io.File;
import java.io.FileFilter;
import org.apache.commons.io.filefilter.SuffixFileFilter;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.signserver.common.util.PathUtil;

/**
 * Unit tests for the AdminWebBean class.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class AdminWebBeanTest {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(AdminWebBeanTest.class);
    
    public AdminWebBeanTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Tests that each XHTML page has a mapping to an existing documentation
     * page.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testGetDocumentationLink() throws Exception {
        LOG.info("getDocumentationLink");
        AdminWebBean instance = new AdminWebBean();
        instance.init();
        
        // First test one we know that should exist
        String result = instance.getDocumentationLink("/workers.xhtml");
        assertNotNull("page for /workers.xhtml", result);
        
        // Then test that each of our pages has a mapping to an existing file
        final File home = PathUtil.getAppHome();
        final File sources = new File(home, "modules/SignServer-Admin-web/src/main/webapp/");
        final File docs = new File(home, "doc/htdocs/");
        final File[] srcFiles = sources.listFiles((FileFilter) new SuffixFileFilter(".xhtml"));
        if (srcFiles.length == 0) {
            throw new Exception("Wrong location for the .xhtml files?");
        }

        for (File srcFile : srcFiles) {
            final String docName = instance.getDocumentationLink("/" + srcFile.getName());
            LOG.debug("Testing mapping /" + srcFile.getName() + " => " + docName);
            assertNotNull("Missing mapping for the /" + srcFile.getName() + " page. Please, update doc-links.properties.", docName);
            final File docFile = new File(docs, docName);
            assertTrue("Missing documentation file: " + docFile.getName() + ". Please, add it or update doc-links.properties.", docFile.exists());
        }
    }
    
}
