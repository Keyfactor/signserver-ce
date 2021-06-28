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

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import javax.ejb.EJBException;
import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.Query;
import org.apache.log4j.Logger;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.Base64PutHashMap;
import org.signserver.common.NoSuchWorkerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerType;
import org.signserver.common.util.SecureXMLDecoder;

/**
 * Entity Service class that acts as migration layer for
 * the old Home Interface for the Worker Config Entity Bean
 * 
 * Contains about the same methods as the EJB 2 entity beans home interface.
 *
 * @version $Id$
 */
public class WorkerConfigDataService implements IWorkerConfigDataService {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(WorkerConfigDataService.class);
    
    private final EntityManager em;

    public WorkerConfigDataService(EntityManager em) {
        this.em = em;
    }

    /**
     * Entity Bean holding info about a workers (service or signer) configuration
     * 
     * @param workerId uniqe Id of the worker 
     * @param configClassPath Class name of the worker implementation
     */
    @Override
    public void create(int workerId, String configClassPath) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Creating worker config data, id=" + workerId);
        }
        WorkerConfigDataBean wcdb = new WorkerConfigDataBean();
        wcdb.setSignerId(workerId);
        final String name = "UnamedWorker" + workerId;
        wcdb.setSignerName(name);
        wcdb.setSignerType(WorkerType.UNKNOWN.getType());

        try {
            final WorkerConfig config = (WorkerConfig) this.getClass().getClassLoader().loadClass(configClassPath).newInstance();
            config.setProperty("NAME", name); // TODO
            setWorkerConfig(workerId, config, wcdb);
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
    private WorkerConfig getWorkerConfig(int workerId) {
        WorkerConfig workerConf = null;
        WorkerConfigDataBean wcdb = em.find(WorkerConfigDataBean.class, workerId);

        if (wcdb != null) {
            workerConf = parseWorkerConfig(wcdb);
        }

        return workerConf;
    }
    
    private WorkerConfig parseWorkerConfig(WorkerConfigDataBean wcdb) {
        final WorkerConfig workerConf = new WorkerConfig();
        SecureXMLDecoder decoder =
                    new SecureXMLDecoder(
                    new ByteArrayInputStream(wcdb.getSignerConfigData().getBytes(StandardCharsets.UTF_8)));

        try {
            HashMap h = (HashMap) decoder.readObject();
            decoder.close();
            // Handle Base64 encoded string values
            HashMap data = new Base64GetHashMap(h);
            workerConf.loadData(data);
            workerConf.upgrade();
        } catch (Exception e) {
            LOG.error(e);
        }

        if (wcdb.getSignerName() != null) {
            workerConf.setProperty("NAME", wcdb.getSignerName());
        }
        final Integer signerType = wcdb.getSignerType();
        if (signerType != null) {
            try {
                workerConf.setProperty("TYPE", WorkerType.fromType(signerType).name());
            } catch (IllegalArgumentException ex) {
                LOG.error("Unsupported worker type: " + signerType + ": " + ex.getLocalizedMessage());
            }
        }

        return workerConf;
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<Integer> findAllIds() {
        final LinkedList<Integer> result = new LinkedList<>();
        Query query = em.createQuery("SELECT w from WorkerConfigDataBean w"); // TODO: More efficient way to just query the IDs
        List<WorkerConfigDataBean> list = (List<WorkerConfigDataBean>) query.getResultList();
        for (WorkerConfigDataBean wcdb : list) {
            result.add(wcdb.getSignerId());
        }
        
        return result;
    }
    
    @Override
     public List<String> findAllNames() {
        final LinkedList<String> result = new LinkedList<>();
        Query query = em.createQuery("SELECT w from WorkerConfigDataBean w"); 
        List<WorkerConfigDataBean> list = (List<WorkerConfigDataBean>) query.getResultList();
        for (WorkerConfigDataBean wcdb : list) {
            result.add(wcdb.getSignerName());
        }
        
        return result;
    }
    
    @Override
    public List<Integer> findAllIds(final WorkerType workerType) {
        final LinkedList<Integer> result = new LinkedList<>();
        Query query;
        if (workerType == null) {
            query = em.createQuery("SELECT w from WorkerConfigDataBean w WHERE w.signerType IS NULL OR w.signerType = :workerType").setParameter("workerType", WorkerType.UNKNOWN.getType());
        } else {
            query = em.createQuery("SELECT w from WorkerConfigDataBean w WHERE w.signerType = :workerType").setParameter("workerType", workerType.getType());
        }
        List<WorkerConfigDataBean> list = (List<WorkerConfigDataBean>) query.getResultList();
        for (WorkerConfigDataBean wcdb : list) {
            result.add(wcdb.getSignerId());
        }
        
        return result;
    }
    
    /**
     * Method that saves the Worker Config to database.
     * 
     * @param signconf Worker configuration
     */
    @Override
    public void setWorkerConfig(int workerId, WorkerConfig signconf) {
        setWorkerConfig(workerId, signconf, null);
    }

    /**
     * Method that removes a worker config
     * 
     * @return true if the removal was successful
     */
    @Override
    public boolean removeWorkerConfig(int workerId) {
        boolean retval = false;
        WorkerConfigDataBean wcdb = em.find(WorkerConfigDataBean.class, workerId);
        if (wcdb != null) {
            em.remove(wcdb);
            retval = true;
        }

        return retval;
    }

    /**
     * Method that saves the Worker Config to database.
     */
    @SuppressWarnings("unchecked")
    private void setWorkerConfig(int workerId, WorkerConfig signconf, WorkerConfigDataBean wcdb) {
        // We must base64 encode string for UTF safety
        HashMap a = new Base64PutHashMap();
        a.putAll((HashMap) signconf.saveData());


        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();

        try (java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos)) {
            encoder.writeObject(a);
        }

        try {
            if (LOG.isDebugEnabled()) {
                LOG.debug("WorkerConfig data: \n" + baos.toString(StandardCharsets.UTF_8.name()));
            }
            if (wcdb == null) {
                wcdb = em.find(WorkerConfigDataBean.class, workerId);
                if (wcdb == null) {
                    create(workerId, WorkerConfig.class.getName());
                    wcdb = em.find(WorkerConfigDataBean.class, workerId);
                }
            }
            wcdb.setSignerConfigData(baos.toString(StandardCharsets.UTF_8.name()));
            
            // Update name
            if (signconf.getProperty("NAME") != null) {
                wcdb.setSignerName(signconf.getProperty("NAME"));
            }
            
            final String type = signconf.getProperty("TYPE");
            if (signconf.getProperty("TYPE") != null) {
                try {
                    wcdb.setSignerType(WorkerType.valueOf(type).getType());
                } catch (IllegalArgumentException ex) {
                    LOG.error("Unable to set worker type: " + ex.getLocalizedMessage());
                    wcdb.setSignerType(WorkerType.UNKNOWN.getType());
                }
            }

            em.persist(wcdb);
        } catch (UnsupportedEncodingException e) {
            throw new EJBException(e);
        }
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.IWorkerConfigDataService#getWorkerProperties(int)
     */
    @Override
    public WorkerConfig getWorkerProperties(int workerId, boolean create) {
        WorkerConfig workerConfig = getWorkerConfig(workerId);
        if (workerConfig == null && create) { // XXX remove 'create' parameter and instead let caller do the 'new'
            workerConfig = new WorkerConfig();
        }
        return workerConfig;
    }

    @Override
    public void populateNameColumn() {
        Query query = em.createQuery("SELECT w from WorkerConfigDataBean w WHERE w.signerName IS NULL"); // TODO: More efficient way to query
        List<WorkerConfigDataBean> list = (List<WorkerConfigDataBean>) query.getResultList();
        if (list.isEmpty()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Found no worker configurations without name column");
            }
        } else {
            LOG.info("Found " + list.size() + " worker configurations without name column");
            for (WorkerConfigDataBean wcdb : list) {
                WorkerConfig config = parseWorkerConfig(wcdb);
                String name = config.getProperty("NAME");
                if (name == null) {
                    name = "UpgradedWorker-" + wcdb.getSignerId();
                }
                LOG.info("Upgrading worker configuration " + wcdb.getSignerId() + " with name " + name);
                wcdb.setSignerName(name);
                em.persist(wcdb);
            }
        }
    }

    @Override
    public int findId(String workerName) throws NoSuchWorkerException {
        final int result;
        try {
            Query query = em.createQuery("SELECT w.signerId from WorkerConfigDataBean w WHERE w.signerName = :name").setParameter("name", workerName);
            query.setMaxResults(1);
            Object o = query.getSingleResult();
            if (o instanceof Integer) {
                result = (Integer) o;
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Query result is " + o);
                }
                throw new NoSuchWorkerException(workerName);
            }
        } catch (NoResultException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No worker named " + workerName + " found: " + ex.getMessage());
            }
            throw new NoSuchWorkerException(workerName);
        }
        return result;
    }
}
