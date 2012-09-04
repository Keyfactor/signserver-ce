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
import java.util.Map;
import javax.ejb.EJBException;
import org.apache.log4j.Logger;
import org.ejbca.util.Base64GetHashMap;
import org.ejbca.util.Base64PutHashMap;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.WorkerConfig;

/**
 * Entity Service class that acts as migration layer for
 * the old Home Interface for the Worker Config Entity Bean
 * 
 * Contains about the same methods as the EJB 2 entity beans home interface.
 *
 * @version $Id$
 */
public class FileBasedWorkerConfigDataService implements IWorkerConfigDataService {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(FileBasedWorkerConfigDataService.class);
    
    /** Audit logger. */
//    private static final ISystemLogger AUDITLOG = SystemLoggerFactory.getInstance().getLogger(WorkerConfigDataService.class);
    
    private File file;

    public FileBasedWorkerConfigDataService(File file) {
//        this.em = em;
        this.file = file;
    }

    /**
     * Entity Bean holding info about a workers (service or signer) configuration
     * 
     * @param workerId uniqe Id of the worker 
     *
     */
    @Override
    public void create(int workerId, String configClassPath) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Creating worker config data, id=" + workerId);
        }
        WorkerConfigDataBean wcdb = new WorkerConfigDataBean();
        wcdb.setSignerId(workerId);

        try {
            setWorkerConfig(workerId, (WorkerConfig) this.getClass().getClassLoader().loadClass(configClassPath).newInstance(), wcdb);
        } catch (Exception e) {
            LOG.error(e);
        }
    }

    /**
     * Returns the value object containing the information of the entity bean.
     * This is the method that should be used to worker config correctly
     * correctly.
     *
     */
    @SuppressWarnings("unchecked")
    @Override
    public WorkerConfig getWorkerConfig(int workerId) {
        WorkerConfig workerConf = null;

        Map<Integer, WorkerConfigDataBean> dataStore = loadData();
        WorkerConfigDataBean wcdb = dataStore.get(workerId);

        if (wcdb != null) {
            java.beans.XMLDecoder decoder;
            try {
                decoder =
                        new java.beans.XMLDecoder(
                        new java.io.ByteArrayInputStream(wcdb.getSignerConfigData().getBytes("UTF8")));
            } catch (UnsupportedEncodingException e) {
                throw new EJBException(e);
            }

            HashMap h = (HashMap) decoder.readObject();
            decoder.close();
            // Handle Base64 encoded string values
            HashMap data = new Base64GetHashMap(h);

            if (data.get(WorkerConfig.CLASS) == null) {
                // Special case, need to upgrade from signserver 1.0
                workerConf = new ProcessableConfig(new WorkerConfig()).getWorkerConfig();
                workerConf.loadData(data);
                workerConf.upgrade();
            } else {
                try {
                    workerConf = new WorkerConfig();
                    workerConf.loadData(data);
                    workerConf.upgrade();
                } catch (Exception e) {
                    LOG.error(e);
                }
            }
        }

        return workerConf;
    }

    /**
     * Method that saves the Worker Config to database.
     */
    @Override
    public void setWorkerConfig(int workerId, WorkerConfig signconf) {
        setWorkerConfig(workerId, signconf, null);
//        auditLog(workerId, "setWorkerConfig");
    }

    /**
     * Method that removes a worker config
     * 
     * @return true if the removal was successful
     */
    @Override
    public boolean removeWorkerConfig(int workerId) {
        boolean retval = false;
        Map<Integer, WorkerConfigDataBean> dataStore = loadData();
        WorkerConfigDataBean wcdb = dataStore.remove(workerId);
        if (wcdb != null) {
            writeData(dataStore);
            retval = true;
        }

        return retval;
    }

    /**
     * Method that saves the Worker Config to database.
     */
    @SuppressWarnings("unchecked")
    private void setWorkerConfig(int workerId, WorkerConfig signconf, WorkerConfigDataBean wcdb) {
        
        Map<Integer, WorkerConfigDataBean> dataStore = loadData();
        
        // We must base64 encode string for UTF safety
        HashMap a = new Base64PutHashMap();
        a.putAll((HashMap) signconf.saveData());


        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();

        java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
        encoder.writeObject(a);
        encoder.close();

        try {
            if (LOG.isDebugEnabled()) {
                LOG.debug("WorkerConfig data: \n" + baos.toString("UTF8"));
            }
            if (wcdb == null) {
                wcdb = dataStore.get(workerId);
            }
            wcdb.setSignerConfigData(baos.toString("UTF8"));
            dataStore.put(workerId, wcdb);
            writeData(dataStore);
            
        } catch (UnsupportedEncodingException e) {
            throw new EJBException(e);
        }
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.IWorkerConfigDataService#getWorkerProperties(int)
     */
    @Override
    public WorkerConfig getWorkerProperties(int workerId) {

        WorkerConfig workerConfig = getWorkerConfig(workerId);
        if (workerConfig == null) {
            create(workerId, WorkerConfig.class.getName());
            workerConfig = getWorkerConfig(workerId);
        }

        return workerConfig;
    }

//    private void auditLog(final int workerId, final String operation) {
//        try {
//            final Map<String, String> logMap = new HashMap<String, String>();
//
//            logMap.put(ISystemLogger.LOG_CLASS_NAME,
//                    WorkerConfigDataService.class.getSimpleName());
//            logMap.put(ISystemLogger.LOG_WORKER_ID, String.valueOf(workerId));
//            logMap.put(IWorkerConfigDataService.LOG_OPERATION,
//                    operation);
//            AUDITLOG.log(logMap);
//        } catch (SystemLoggerException ex) {
//            LOG.error("Audit log failure", ex);
//            throw new EJBException("Audit log failure", ex);
//        }
//    }

    private Map<Integer, WorkerConfigDataBean> loadData() {
        HashMap<Integer, WorkerConfigDataBean> result = new HashMap<Integer, WorkerConfigDataBean>();
        ObjectInputStream in = null;
        try {
            in = new ObjectInputStream(new FileInputStream(file));
            result = (HashMap<Integer, WorkerConfigDataBean>) in.readObject();
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

    private void writeData(Map<Integer, WorkerConfigDataBean> dataStore) {
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
