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
import java.util.HashMap;
import java.util.Map;
import org.apache.log4j.Logger;

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
    
    private File file;

    public FileBasedKeyUsageCounterDataService(File file) {
        this.file = file;
    }

    /**
     * Entity Bean holding info about a workers (service or signer) configuration
     * 
     * @param workerId uniqe Id of the worker 
     *
     */
    @Override
    public void create(final String keyHash) { // TODO: Synchronization
        if (LOG.isDebugEnabled()) {
            LOG.debug("Creating keyusagecounter " + keyHash);
        }
        Map<String, Long> data = loadData();
        if (data == null) { // TODO: How to handle this case safely
            data = new HashMap<String, Long>();
        }
        data.put(keyHash, 0L);
        writeData(data);
    }
    
    @Override
    public KeyUsageCounter getCounter(final String keyHash) { // TODO: Synchronization
        final KeyUsageCounter result;
        
        Map<String, Long> data = loadData();
        final Long value = data.get(keyHash);
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
        return result;
    }

    @Override
    public boolean incrementIfWithinLimit(String keyHash, long limit) { // TODO: Synchronization
        final boolean result;
        final Map<String, Long> data = loadData();
        final Long value = data.get(keyHash);
        if (value == null) {
            result = false;
        } else if (limit >= 0 && value >= limit) {
            result = false;
        } else {
            data.put(keyHash, value + 1);
            writeData(data);
            result = true;
        }
        return result;
    }

    @Override
    public boolean isWithinLimit(String keyHash, long keyUsageLimit) { // TODO: Synchronization
        final Map<String, Long> data = loadData();
        final Long value = data.get(keyHash);
        return value != null && value < keyUsageLimit;
    }
    
    private Map<String, Long> loadData() {
        HashMap<String, Long> result = new HashMap<String, Long>();
        ObjectInputStream in = null;
        try {
            in = new ObjectInputStream(new FileInputStream(file));
            result = (HashMap<String, Long>) in.readObject();
        } catch (ClassNotFoundException ex) {
            LOG.error("Could not load data from " + file.getAbsolutePath(), ex);
        } catch (IOException ex) {
            LOG.error("Could not load data from " + file.getAbsolutePath(), ex);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ignored) {} // NOPMD
}
        }
        return result;
    }

    private void writeData(Map<String, Long> dataStore) {
        ObjectOutputStream out = null;
        try {
            out = new ObjectOutputStream(new FileOutputStream(file));
            out.writeObject(dataStore);
        } catch (IOException ex) {
            LOG.error("Could not write data to " + file.getAbsolutePath(), ex);
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException ignored) {} // NOPMD
            }
        }
    }
        

}
