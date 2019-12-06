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
package org.signserver.common.util;

import java.io.File;
import java.io.FileNotFoundException;
import org.apache.log4j.Logger;

/**
 * Utility methods dealing with file system paths.
 * Typically used by the JUnit tests that uses files in SIGNSERVER_HOME.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class PathUtil {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(PathUtil.class);

    private static final String APPLICATION_SPECIFIC_FILE = "bin/signclient";

    /**
     * Gets the application directory (ie. SIGNSERVER_HOME).
     * The directory is found by moving up the directory tree until a folder
     * with SignServer specific files are found.
     * Also tries to create a tmp folder if it does not already exists.
     * @return the application directory
     * @throws java.io.FileNotFoundException in case the application directory
     * could not be found
     */
    public static File getAppHome() throws FileNotFoundException {
        File result = null;
        final File cwd = new File(".");
        File f = cwd; // Start with current working directory;
        for (int i = 0; f != null && i < 10; i++) {
            if (new File(f, APPLICATION_SPECIFIC_FILE).exists()) {
                result = f.getAbsoluteFile();
                break;
            }
            f = f.getAbsoluteFile().getParentFile();
        }
        if (result == null) {
            throw new FileNotFoundException("Application home folder could not be found. Started search with CWD: " + cwd.getAbsolutePath());
        }
        
        // Try to create a tmp folder
        final File tmpFolder = new File(result, "tmp");
        if (!tmpFolder.exists()) {
            if (!tmpFolder.mkdir()) {
                LOG.warn("Unable to create tmp folder: " + tmpFolder.getAbsolutePath());
            }
        }

        return result;
    }
}
