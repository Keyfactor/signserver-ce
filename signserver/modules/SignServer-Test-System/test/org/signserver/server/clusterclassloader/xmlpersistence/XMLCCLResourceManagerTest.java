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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Set;

import org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean;

import junit.framework.TestCase;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public class XMLCCLResourceManagerTest extends TestCase {

    protected void setUp() throws Exception {
        super.setUp();
        XMLCCLResourceManager.xMLFileLocation = "tmp/cclxmlfile.xml";
    }

    public void testPopulateResource() throws FileNotFoundException, IOException {
        File xmlFile = new File("tmp/cclxmlfile.xml");
        if (xmlFile.exists()) {
            xmlFile.delete();
        }

        XMLCCLResourceManager.addResource("MOD1", "server", 1, "jar1.jar", "jar1.resource1", "java.util.HashMap;java.lang.String", "desc",
                "comment", "resourceData".getBytes());
        XMLCCLResourceManager.addResource("MOD1", "server", 1, "jar1.jar", "jar1.resource2", "", "desc",
                "comment", "resourceData".getBytes());
        XMLCCLResourceManager.addResource("MOD1", "server", 1, "jar1.jar", "jar1.resource3", "java.util.HashMap", "desc",
                "comment", "resourceData".getBytes());
        XMLCCLResourceManager.addResource("MOD1", "server", 1, "jar2.jar", "jar2.resource1", "java.util.HashMap;java.util.Vector", "desc",
                "comment", "resourceData".getBytes());
        XMLCCLResourceManager.addResource("MOD1", "server", 1, "jar2.jar", "jar2.resource2", "java.lang.String", "desc",
                "comment", "resourceData".getBytes());
        XMLCCLResourceManager.addResource("MOD1", "server", 1, "jar2.jar", "jar2.resource3", "", "desc",
                "comment", "resourceData".getBytes());
        XMLCCLResourceManager.addResource("MOD1", "admin", 1, "jar2.jar", "jar2.resource1", "", "desc",
                "comment", "resourceData".getBytes());
        XMLCCLResourceManager.addResource("MOD1", "admin", 1, "jar2.jar", "jar2.resource2", "", "desc",
                "comment", "resourceData".getBytes());
        XMLCCLResourceManager.addResource("MOD1", "admin", 1, "jar2.jar", "jar2.resource3", "", "desc",
                "comment", "resourceData".getBytes());
        XMLCCLResourceManager.addResource("MOD1", "server", 2, "jar1.jar", "jar1.resource1", "", "desc",
                "comment", "resourceData".getBytes());
        XMLCCLResourceManager.addResource("MOD1", "server", 2, "jar1.jar", "jar1.resource2", "", "desc",
                "comment", "resourceData".getBytes());
        XMLCCLResourceManager.addResource("MOD1", "server", 2, "jar1.jar", "jar1.resource3", "", "desc",
                "comment", "resourceData".getBytes());
        XMLCCLResourceManager.addResource("MOD1", "server", 2, "jar2.jar", "jar2.resource1", "", "desc",
                "comment", "resourceData".getBytes());
        XMLCCLResourceManager.addResource("MOD1", "server", 2, "jar2.jar", "jar2.resource2", "", "desc",
                "comment", "resourceData".getBytes());
        XMLCCLResourceManager.addResource("MOD1", "server", 2, "jar2.jar", "jar2.resource3", "", "desc",
                "comment", "resourceData".getBytes());
        XMLCCLResourceManager.addResource("MOD2", "server", 1, "jar1.jar", "jar1.resource1", "", "desc",
                "comment", "resourceData".getBytes());
        XMLCCLResourceManager.addResource("MOD2", "server", 1, "jar1.jar", "jar1.resource2", "", "desc",
                "comment", "resourceData".getBytes());
        XMLCCLResourceManager.addResource("MOD2", "server", 1, "jar1.jar", "jar1.resource3", "", "desc",
                "comment", "resourceData".getBytes());
        XMLCCLResourceManager.addResource("MOD2", "server", 1, "jar2.jar", "jar2.resource1", "", "desc",
                "comment", "resourceData".getBytes());
        XMLCCLResourceManager.addResource("MOD2", "server", 1, "jar2.jar", "jar2.resource2", "", "desc",
                "comment", "resourceData".getBytes());
        XMLCCLResourceManager.addResource("MOD2", "server", 1, "jar2.jar", "jar2.resource3", "", "desc",
                "comment", "resourceData".getBytes());

        //save it
        XMLCCLResourceManager.addResource(null, null, 0, null, null, null, null,
                null, null);

        assertTrue(xmlFile.exists());
        assertTrue(new FileInputStream(xmlFile).available() != 0);

    }

    public void testListAllModules() throws Exception {
        assertTrue(XMLCCLResourceManager.listAllModules().length == 2);
        assertTrue(XMLCCLResourceManager.listAllModules()[0].equals("MOD1") || XMLCCLResourceManager.listAllModules()[0].equals("MOD2"));
        assertTrue(XMLCCLResourceManager.listAllModules()[1].equals("MOD1") || XMLCCLResourceManager.listAllModules()[1].equals("MOD2"));
    }

    public void testListAllModuleVersions() throws Exception {
        assertTrue(XMLCCLResourceManager.listAllModuleVersions("MOD1").length == 2);
        assertTrue(XMLCCLResourceManager.listAllModuleVersions("MOD1")[0] == 1 || XMLCCLResourceManager.listAllModuleVersions("MOD1")[0] == 2);
        assertTrue(XMLCCLResourceManager.listAllModuleVersions("MOD1")[1] == 1 || XMLCCLResourceManager.listAllModuleVersions("MOD1")[1] == 2);
        assertTrue(XMLCCLResourceManager.listAllModuleVersions("MOD2").length == 1);
        assertTrue(XMLCCLResourceManager.listAllModuleVersions("MOD2")[0] == 1);
        assertTrue(XMLCCLResourceManager.listAllModuleVersions("MOD3").length == 0);
    }

    public void testListAllModuleParts() throws Exception {
        assertTrue(XMLCCLResourceManager.listAllModuleParts("MOD1", 1).length == 2);
        assertTrue(XMLCCLResourceManager.listAllModuleParts("MOD1", 1)[0].equals("server") || XMLCCLResourceManager.listAllModuleParts("MOD1", 1)[0].equals("admin"));
        assertTrue(XMLCCLResourceManager.listAllModuleParts("MOD1", 1)[1].equals("server") || XMLCCLResourceManager.listAllModuleParts("MOD1", 1)[1].equals("admin"));
        assertTrue(XMLCCLResourceManager.listAllModuleParts("MOD1", 2).length == 1);
        assertTrue(XMLCCLResourceManager.listAllModuleParts("MOD1", 2)[0].equals("server"));
        assertTrue(XMLCCLResourceManager.listAllModuleParts("MOD2", 1).length == 1);
        assertTrue(XMLCCLResourceManager.listAllModuleParts("MOD2", 1)[0].equals("server"));
        assertTrue(XMLCCLResourceManager.listAllModuleParts("MOD2", 2).length == 0);
        assertTrue(XMLCCLResourceManager.listAllModuleParts("MOD3", 1).length == 0);
    }

    public void testGetJarNames() throws Exception {
        assertTrue(XMLCCLResourceManager.getJarNames("MOD1", "server", 1).length == 2);
        assertTrue(XMLCCLResourceManager.getJarNames("MOD1", "server", 1)[0].equals("jar1.jar") || XMLCCLResourceManager.getJarNames("MOD1", "server", 1)[0].equals("jar2.jar"));
        assertTrue(XMLCCLResourceManager.getJarNames("MOD1", "server", 1)[1].equals("jar1.jar") || XMLCCLResourceManager.getJarNames("MOD1", "server", 1)[1].equals("jar2.jar"));
        assertTrue(XMLCCLResourceManager.getJarNames("MOD1", "admin", 1).length == 1);
        assertTrue(XMLCCLResourceManager.getJarNames("MOD1", "admin", 1)[0].equals("jar2.jar"));
        assertTrue(XMLCCLResourceManager.getJarNames("MOD1", "server", 2).length == 2);
        assertTrue(XMLCCLResourceManager.getJarNames("MOD1", "server", 2)[0].equals("jar1.jar") || XMLCCLResourceManager.getJarNames("MOD1", "server", 2)[0].equals("jar2.jar"));
        assertTrue(XMLCCLResourceManager.getJarNames("MOD1", "server", 2)[1].equals("jar1.jar") || XMLCCLResourceManager.getJarNames("MOD1", "server", 2)[1].equals("jar2.jar"));
        assertTrue(XMLCCLResourceManager.getJarNames("MOD2", "server", 1).length == 2);
        assertTrue(XMLCCLResourceManager.getJarNames("MOD2", "server", 1)[0].equals("jar1.jar") || XMLCCLResourceManager.getJarNames("MOD2", "server", 1)[0].equals("jar2.jar"));
        assertTrue(XMLCCLResourceManager.getJarNames("MOD2", "server", 1)[1].equals("jar1.jar") || XMLCCLResourceManager.getJarNames("MOD2", "server", 1)[1].equals("jar2.jar"));
        assertTrue(XMLCCLResourceManager.getJarNames("MOD3", "server", 2).length == 0);
    }

    public void testGetAvailableResources() throws Exception {
        HashMap<String, IClusterClassLoaderDataBean> resources = XMLCCLResourceManager.getAvailableResources("MOD1", "server", 1);
        assertTrue(resources != null);
        assertTrue(resources.size() == 6);
        assertTrue(resources.get("jar1.resource1") != null);
        assertTrue(resources.get("jar1.resource2") != null);
        assertTrue(resources.get("jar1.resource3") != null);
        assertTrue(resources.get("jar2.resource1") != null);
        assertTrue(resources.get("jar2.resource2") != null);
        assertTrue(resources.get("jar2.resource3") != null);
        resources = XMLCCLResourceManager.getAvailableResources("MOD1", "server", 2);
        assertTrue(resources != null);
        assertTrue(resources.size() == 6);
        assertTrue(resources.get("jar1.resource1") != null);
        assertTrue(resources.get("jar1.resource2") != null);
        assertTrue(resources.get("jar1.resource3") != null);
        assertTrue(resources.get("jar2.resource1") != null);
        assertTrue(resources.get("jar2.resource2") != null);
        assertTrue(resources.get("jar2.resource3") != null);
        resources = XMLCCLResourceManager.getAvailableResources("MOD1", "admin", 1);
        assertTrue(resources != null);
        assertTrue(resources.size() == 3);
        assertTrue(resources.get("jar2.resource1") != null);
        assertTrue(resources.get("jar2.resource2") != null);
        assertTrue(resources.get("jar2.resource3") != null);
        resources = XMLCCLResourceManager.getAvailableResources("MOD2", "server", 1);
        assertTrue(resources != null);
        assertTrue(resources.size() == 6);
        assertTrue(resources.get("jar1.resource1") != null);
        assertTrue(resources.get("jar1.resource2") != null);
        assertTrue(resources.get("jar1.resource3") != null);
        assertTrue(resources.get("jar2.resource1") != null);
        assertTrue(resources.get("jar2.resource2") != null);
        assertTrue(resources.get("jar2.resource3") != null);
        resources = XMLCCLResourceManager.getAvailableResources("MOD3", "server", 1);
        assertTrue(resources != null);
        assertTrue(resources.size() == 0);
        resources = XMLCCLResourceManager.getAvailableResources("MOD2", "server", 2);
        assertTrue(resources != null);
        assertTrue(resources.size() == 0);
    }

    public void testGetVersionsOfModule() throws Exception {
        Set<Integer> vers = XMLCCLResourceManager.getVersionsOfModule("MOD1");
        assertTrue(vers.size() == 2);
        assertTrue(vers.contains(1));
        assertTrue(vers.contains(2));
        vers = XMLCCLResourceManager.getVersionsOfModule("MOD2");
        assertTrue(vers.size() == 1);
        assertTrue(vers.contains(1));
        vers = XMLCCLResourceManager.getVersionsOfModule("MOD3");
        assertTrue(vers.size() == 0);
    }

    public void testRemoveModule() throws Exception {
        XMLCCLResourceManager.removeModulePart("MOD2", "server", 1);
        Set<Integer> vers = XMLCCLResourceManager.getVersionsOfModule("MOD2");
        assertTrue(vers.size() == 0);

        assertTrue(XMLCCLResourceManager.listAllModules().length == 1);

        XMLCCLResourceManager.removeModulePart("MOD1", "server", 1);
        XMLCCLResourceManager.removeModulePart("MOD1", "admin", 1);
        vers = XMLCCLResourceManager.getVersionsOfModule("MOD1");
        assertTrue(vers.size() == 1);
        assertTrue(vers.contains(2));
        XMLCCLResourceManager.removeModulePart("MOD3", "server", 1);

        File xmlFile = new File("tmp/cclxmlfile.xml");
        if (xmlFile.exists()) {
            xmlFile.delete();
        }
    }
}
