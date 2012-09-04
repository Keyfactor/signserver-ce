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
package org.signserver.server.config.entities;

import java.io.*;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.apache.log4j.Logger;

/**
 * Entity Service class that acts as migration layer for
 * the old Home Interface for the GlobalConfigurationData Entity Bean
 * 
 * Contains about the same methods as the EJB 2 entity beans home interface.
 *
 * @version $Id$
 */
public class FileBasedGlobalConfigurationDataService implements IGlobalConfigurationDataService {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(FileBasedGlobalConfigurationDataService.class);

    private File file;

    public FileBasedGlobalConfigurationDataService(File file) {
        this.file = file;
    }

    @Override
    public void setGlobalProperty(String completekey, String value) {
        Map<String, GlobalConfigurationDataBean> dataStore = loadData();
        GlobalConfigurationDataBean data = dataStore.get(completekey);
        if (data == null) {
            data = new GlobalConfigurationDataBean();
            data.setPropertyKey(completekey);
            data.setPropertyValue(value);
            dataStore.put(completekey, data);
        } else {
            data.setPropertyValue(value);
        }
        writeData(dataStore);
    }

    @Override
    public boolean removeGlobalProperty(String completekey) {
        boolean retval = false;
        Map<String, GlobalConfigurationDataBean> dataStore = loadData();
        GlobalConfigurationDataBean data = dataStore.remove(completekey);
        if (data != null) {
            writeData(dataStore);
            retval = true;
        }
        return retval;
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<GlobalConfigurationDataBean> findAll() {
        Map<String, GlobalConfigurationDataBean> dataStore = loadData();

        return new LinkedList<GlobalConfigurationDataBean>(dataStore.values());
    }
    
    private Map<String, GlobalConfigurationDataBean> loadData() {
        HashMap<String, GlobalConfigurationDataBean> result = new HashMap<String, GlobalConfigurationDataBean>();
        ObjectInputStream in = null;
        try {
            in = new ObjectInputStream(new FileInputStream(file));
            result = (HashMap<String, GlobalConfigurationDataBean>) in.readObject();
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

    private void writeData(Map<String, GlobalConfigurationDataBean> dataStore) {
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
