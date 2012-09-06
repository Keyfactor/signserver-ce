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
package org.signserver.server.nodb;

import java.io.File;
import org.apache.log4j.Logger;
import org.signserver.common.CompileTimeSettings;

/**
 * Manages the file based database.
 *
 * The only instance of this class can be used for synchronizing access to the 
 * file based database.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class FileBasedDatabaseManager {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(FileBasedDatabaseManager.class);
    
    private static FileBasedDatabaseManager instance = new FileBasedDatabaseManager(new File(CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.FILEBASED_DB_FOLDER)));
    
    private File dataFolder;
    
    private FileBasedDatabaseManager(File dataFolder) {
        this.dataFolder = dataFolder;
    }

    public static FileBasedDatabaseManager getInstance() {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Returning instance: " + instance);
        }
        return instance;
    }

    public File getDataFolder() {
        return dataFolder;
    }
    
}
