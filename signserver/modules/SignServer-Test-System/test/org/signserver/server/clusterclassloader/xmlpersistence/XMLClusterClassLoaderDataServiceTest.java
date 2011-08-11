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
package org.signserver.server.clusterclassloader.xmlpersistence;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Collection;

import org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean;

import junit.framework.TestCase;

/**
 * TODO: Document me!
 * 
 * @author Philip Vendil 2 aug 2008
 * @version $Id$
 */
public class XMLClusterClassLoaderDataServiceTest extends TestCase {

    /* (non-Javadoc)
     * @see junit.framework.TestCase#setUp()
     */
    protected void setUp() throws Exception {
        super.setUp();
        XMLCCLResourceManager.xMLFileLocation = "tmp/cclxmlfile.xml";
    }

    /**
     * Test method for {@link org.signserver.server.clusterclassloader.xmlpersistence.XMLClusterClassLoaderDataService#findByResourceName(java.lang.String)}.
     * @throws IOException 
     * @throws FileNotFoundException 
     */
    public void testFindByResourceName() throws FileNotFoundException, IOException {
        XMLCCLResourceManagerTest pretest = new XMLCCLResourceManagerTest();
        pretest.testPopulateResource();

        XMLClusterClassLoaderDataService s = new XMLClusterClassLoaderDataService("MOD1", "server", 1);
        IClusterClassLoaderDataBean data = s.findByResourceName("jar1.resource1");
        assertTrue(data.getResourceName().equals("jar1.resource1"));
        s = new XMLClusterClassLoaderDataService("MOD1", "server", 2);
        data = s.findByResourceName("jar1.resource1");
        assertTrue(data.getResourceName().equals("jar1.resource1"));
        s = new XMLClusterClassLoaderDataService("MOD2", "server", 1);
        data = s.findByResourceName("jar2.resource1");
        assertTrue(data.getResourceName().equals("jar2.resource1"));
    }

    /**
     * Test method for {@link org.signserver.server.clusterclassloader.xmlpersistence.XMLClusterClassLoaderDataService#findResources()}.
     */
    public void testFindResources() {
        XMLClusterClassLoaderDataService s = new XMLClusterClassLoaderDataService("MOD1", "server", 1);
        Collection<IClusterClassLoaderDataBean> result = s.findResources();
        assertTrue(result.size() == 6);
        s = new XMLClusterClassLoaderDataService("MOD1", "admin", 1);
        result = s.findResources();
        assertTrue(result.size() == 3);
        s = new XMLClusterClassLoaderDataService("MOD2");
        result = s.findResources();
        assertTrue(result.size() == 6);
        s = new XMLClusterClassLoaderDataService("MOD3");
        result = s.findResources();
        assertTrue(result.size() == 0);
    }

    /**
     * Test method for {@link org.signserver.server.clusterclassloader.xmlpersistence.XMLClusterClassLoaderDataService#findLatestVersionOfModule(java.lang.String)}.
     */
    public void testFindLatestVersionOfModule() {
        XMLClusterClassLoaderDataService s = new XMLClusterClassLoaderDataService("MOD1");
        assertTrue(s.findLatestVersionOfModule("MOD1") == 2);
        s = new XMLClusterClassLoaderDataService("MOD3");
        assertTrue(s.findLatestVersionOfModule("MOD2") == 1);
        s = new XMLClusterClassLoaderDataService("MOD3");
        assertTrue(s.findLatestVersionOfModule("MOD3") == 0);
    }

    /**
     * Test method for {@link org.signserver.server.clusterclassloader.xmlpersistence.XMLClusterClassLoaderDataService#findImplementorsInModule(java.lang.String)}.
     */
    public void testFindImplementorsInModule() {
        XMLClusterClassLoaderDataService s = new XMLClusterClassLoaderDataService("MOD1", "server", 1);
        Collection<IClusterClassLoaderDataBean> result = s.findImplementorsInModule("java.util.HashMap");
        assertTrue(result.size() == 3);
    }
}
