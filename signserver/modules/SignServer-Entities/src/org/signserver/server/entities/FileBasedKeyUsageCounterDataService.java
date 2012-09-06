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
package org.signserver.server.entities;

import java.io.*;
import org.apache.log4j.Logger;
import org.signserver.server.nodb.FileBasedDatabaseManager;

/**
 * Entity Service class that acts as migration layer for
 * the old Home Interface for the Worker Config Entity Bean
 * 
 * Contains about the same methods as the EJB 2 entity beans home interface.
 *
 * @version $Id$
 */
public class FileBasedKeyUsageCounterDataService implements IKeyUsageCounterDataService {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(FileBasedKeyUsageCounterDataService.class);
    
    private final FileBasedDatabaseManager manager;
    private File folder;
    private static final String PREFIX = "kuc-";
    private static final String SUFFIX = ".dat";

    public FileBasedKeyUsageCounterDataService(FileBasedDatabaseManager manager) {
        this.manager = manager;
        this.folder = manager.getDataFolder();
    }

    /**
     * Entity Bean holding info about a workers (service or signer) configuration
     * 
     * @param workerId uniqe Id of the worker 
     *
     */
    @Override
    public void create(final String keyHash) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Creating keyusagecounter " + keyHash);
        }
        try {
            synchronized (manager) {
                Long data = loadData(keyHash);
                if (data == null) {
                    writeData(keyHash, 0L);
                }
            }
        } catch (IOException ex) {
            throw new RuntimeException("Could not load from or write data to file based database", ex);
        }
    }
    
    @Override
    public KeyUsageCounter getCounter(final String keyHash) {
        final KeyUsageCounter result;
        try {
            final Long value;
            synchronized (manager) {
                value  = loadData(keyHash);
            }
            if (value == null) {
                result = null;
            } else {
                result = new KeyUsageCounter(keyHash) { // TODO:  This method would be better if only returned the value instead of a KeyUsageCounter object

                    @Override
                    public long getCounter() {
                        return value;
                    }

                };
            }
        } catch (IOException ex) {
            throw new RuntimeException("Could not load from or write data to file based database", ex);
        }
        return result;
    }

    @Override
    public boolean incrementIfWithinLimit(String keyHash, long limit) {
        final boolean result;
        try {
            synchronized (manager) {
                final Long value = loadData(keyHash);
                if (value == null) {
                    result = false;
                } else if (limit >= 0 && value >= limit) {
                    result = false;
                } else {
                    writeData(keyHash, value + 1);
                    result = true;
                }
            }
            return result;
        } catch (IOException ex) {
            throw new RuntimeException("Could not load from or write data to file based database", ex);
        }
    }

    @Override
    public boolean isWithinLimit(String keyHash, long keyUsageLimit) {
        try {
            final Long value;
            synchronized (manager) {
                value  = loadData(keyHash);
            }
            return value != null && value < keyUsageLimit;
        } catch (IOException ex) {
            throw new RuntimeException("Could not load from or write data to file based database", ex);
        }
    }
    
    private Long loadData(String keyHash) throws IOException {
        assert Thread.holdsLock(manager);
        Long result = null;
        final File file = new File(folder, PREFIX + keyHash + SUFFIX);
        if (file.length() > 0) {
            BufferedReader in = null;
            try {
                in = new BufferedReader(new InputStreamReader(new FileInputStream(file)));
                final String line = in.readLine();
                result = Long.valueOf(line);
            } catch (FileNotFoundException ignored) { // NOPMD
            } finally {
                if (in != null) {
                    try {
                        in.close();
                    } catch (IOException ignored) {} // NOPMD
                }
            }
        }
        return result;
    }

    private void writeData(String keyHash, Long value) {
        assert Thread.holdsLock(manager);
        final File file = new File(folder, PREFIX + keyHash + SUFFIX);
        
        BufferedWriter out = null;
        try {
            out = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file)));
            out.write(String.valueOf(value));
        } catch (IOException ex) {
            LOG.error("Could not write data to " + folder.getAbsolutePath(), ex);
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException ignored) {} // NOPMD
            }
        }
    }
        

}
