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
package org.signserver.common;

import java.io.File;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.apache.log4j.Logger;

/**
 * Setting built-in at deploy time.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class DeployTimeSettings {
    /** Logger for this class */
    private static Logger LOG = Logger.getLogger(DeployTimeSettings.class);
    
    private static DeployTimeSettings instance;
    private static CompileTimeSettings compileTimeSettings;
   
    private static int MAX_P11_LIBRARIES = 256;
    
    private static String P11_LIBRARY_PROPERTY_PREFIX = "cryptotoken.p11.lib.";
    private static String P11_LIBRARY_PROPERTY_NAME_SUFFIX = ".name";
    private static String P11_LIBRARY_PROPERTY_FILE_SUFFIX = ".file";
    
    private Map<String, String> p11LibraryMapping = new HashMap<String, String>();
    
    static {
        compileTimeSettings = CompileTimeSettings.getInstance();
    }
    
    private DeployTimeSettings() {
        initP11Libraries();
    }
    
    private void initP11Libraries() {
        for (int i = 0; i < MAX_P11_LIBRARIES; i++) {
            final String name =
                    compileTimeSettings.getProperty(P11_LIBRARY_PROPERTY_PREFIX + i +
                                           P11_LIBRARY_PROPERTY_NAME_SUFFIX);
            final String path =
                    compileTimeSettings.getProperty(P11_LIBRARY_PROPERTY_PREFIX + i +
                                           P11_LIBRARY_PROPERTY_FILE_SUFFIX);

            if (name != null) {
                if (path == null) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("No P11 library path specified for index " + i
                                + " with name: " + name);
                    }
                    continue;
                }
                
                final File libraryFile = new File(path);
                
                
                
                if (!libraryFile.isFile()) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Non-existent library path: " + path);
                    }
                    continue;
                }
                
                p11LibraryMapping.put(name, path);
            }
        }
    }
    
    /**
     * Given a shared library name as defined by deploy-time settings,
     * return the shared library file mapped to that name (if available).
     * 
     * @param name
     * @return shared library path or null if name is unknown
     */
    public String getP11SharedLibraryFileForName(final String name) {
        return p11LibraryMapping.get(name);
    }
    
    /**
     * Return a list a of valid shared library names.
     * 
     * @return List of names
     */
    public Set<String> getP11SharedLibraryNames() {
        return p11LibraryMapping.keySet();
    }
    
    /**
     * Returns true if the specified path points to a defined library.
     * 
     * @param path
     * @return 
     */
    public boolean isP11LibraryExisting(final String path) {
        return p11LibraryMapping.containsValue(path);
    }
    
    public static DeployTimeSettings getInstance() {
        if (instance == null) {
            instance = new DeployTimeSettings();
        }
        return instance;
    }
}
