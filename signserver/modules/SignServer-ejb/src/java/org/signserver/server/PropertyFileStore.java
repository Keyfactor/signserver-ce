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
package org.signserver.server;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Iterator;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.WorkerConfig;

/**
 * Class in charge of storing/loading the current configuration from file
 * in a Property format. This is used in the MailSigner build.
 * 
 * It manages GlobalConfiguration and WorkerConfigurations in much the same way
 * as the EJB variant, but in the back-end stores everything to file.
 * 
 * FIXME: Consider removing this as it is only used by the old MailSigner
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class PropertyFileStore {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(PropertyFileStore.class);
    
    private static PropertyFileStore instance;
    
    private final String fileLocation;
    
    private Properties propertyStore;

    /**
     * Method used to retrieve the PropertyFileStore. 
     *  
     * @return the singleton instance of the PropertyFileStore
     */
    public static PropertyFileStore getInstance() {
        if (instance == null) {
            String phoenixhome = System.getenv("PHOENIX_HOME");
            File confDir = new File(phoenixhome + "/conf");
            if (phoenixhome != null && confDir.exists()) {
                instance = new PropertyFileStore(phoenixhome + "/conf/mailsignerdata.properties");
            }
        }

        if (instance == null) {
            String signserverhome = System.getenv("SIGNSERVER_HOME");
            if (signserverhome == null) {
                LOG.error("Error: Environment variable SIGNSERVER_HOME isn't set");
            }
            instance = new PropertyFileStore(signserverhome + "/extapps/james/conf/mailsignerdata.properties");
        }

        return instance;
    }

    /**
     *  Method used to retrieve the PropertyFileStore from a specified (non-default)
     *  storage location. This method should only be used from automated testscripts.
     *  
     * @param fileLocation the path to the property file to use.
     * @return the singleton instance of the PropertyFileStore
     */
    public static PropertyFileStore getInstance(String fileLocation) {
        if (instance == null) {
            instance = new PropertyFileStore(fileLocation);
        }

        return instance;
    }

    private PropertyFileStore(String fileLocation) {
        this.fileLocation = fileLocation;
        init();
    }

    /**
     * Method that reads the property file and initializes the current properties.
     */
    private void init() {
        propertyStore = new Properties();
        File file = new File(fileLocation);
        if (file.exists() && !file.isDirectory()) {
            try {
                propertyStore.load(new FileInputStream(file));
            } catch (Exception e) {
                LOG.error("Error reading global property file : " + fileLocation + ", Exception :", e);
            }
        }

    }

    /**
     * Method used to reload the current configuration.
     */
    public void reload() {
        init();
    }

    /**
     * Method used to reload the current configuration.
     */
    private void save() {
        try {
            FileOutputStream fos = new FileOutputStream(fileLocation);
            propertyStore.store(fos, "SignServer/MailServer Configuration Store. Only edit this file if you know what you are doing.");
        } catch (IOException e) {
            LOG.error("Error saving global property file : " + fileLocation + ", Exception :", e);
        }
    }

    /**
     * Method used to set a global property value to the backed property file.
     * 
     * @param scope scope one of GlobalConfiguration.SCOPE_ constants
     * @param key the key used
     * @param value of the configuration.
     */
    public void setGlobalProperty(String scope, String key, String value) {
        propertyStore.setProperty(propertyKeyHelper(scope, key), value);
        save();
    }

    /**
     * Method used to remove a global property value to the backed property file.
     * 
     * @param scope scope one of GlobalConfiguration.SCOPE_ constants
     * @param key the key used
     */
    public void removeGlobalProperty(String scope, String key) {
        propertyStore.remove(propertyKeyHelper(scope, key));
        save();
        reload();
    }

    /**
     * Returns the current GlobalConfiguration read from file.
     * 
     */
    public GlobalConfiguration getGlobalConfiguration() {
        Properties properties = new Properties();

        Iterator<Object> iter = propertyStore.keySet().iterator();
        while (iter.hasNext()) {
            String rawkey = (String) iter.next();
            if (rawkey.startsWith(GlobalConfiguration.SCOPE_NODE)) {
                String key = rawkey.replaceFirst(WorkerConfig.getNodeId() + ".", "");
                properties.setProperty(key, propertyStore.getProperty(rawkey));
            } else {
                if (rawkey.startsWith(GlobalConfiguration.SCOPE_GLOBAL)) {
                    properties.setProperty(rawkey, propertyStore.getProperty(rawkey));
                }
            }
        }

        GlobalConfiguration retval = new GlobalConfiguration(properties, GlobalConfiguration.STATE_INSYNC);
        return retval;
    }

    /**
     * Method returning the WorkerConfig for the given workerID
     * @param workerId unique Id of the worker
     * @return the WorkerConfig if the given Id isn't configured in the global
     * configuration never null.
     */
    public WorkerConfig getWorkerProperties(int workerId) {
        WorkerConfig workerConfig = new WorkerConfig();
        Iterator<Object> iter = propertyStore.keySet().iterator();
        String workerPrefix = GlobalConfiguration.WORKERPROPERTY_BASE + workerId + ".";
        while (iter.hasNext()) {
            String rawkey = (String) iter.next();
            if (rawkey.startsWith(workerPrefix)) {
                String key = rawkey.substring(workerPrefix.length());
                workerConfig.setProperty(key, propertyStore.getProperty(rawkey));
            }
        }

        return workerConfig;
    }

    /**
     * Method used to set a specific worker property.
     *  
     */
    public void setWorkerProperty(int workerId, String key, String value) {
        propertyStore.setProperty(GlobalConfiguration.WORKERPROPERTY_BASE + workerId + "." + key.toUpperCase(), value);
        save();
    }

    /**
     * Method used to remove a specific worker property.
     *  
     */
    public void removeWorkerProperty(int workerId, String key) {
        propertyStore.remove(GlobalConfiguration.WORKERPROPERTY_BASE + workerId + "." + key.toUpperCase());
        save();
    }

    /**
     * Method used to remove all properties associated to a workerId
     * @param workerId unique id of worker to remove all properties for.
     */
    public void removeAllWorkerProperties(int workerId) {
        Iterator<Object> iter = propertyStore.keySet().iterator();
        String workerPrefix = GlobalConfiguration.WORKERPROPERTY_BASE + workerId + ".";
        while (iter.hasNext()) {
            String rawkey = (String) iter.next();
            if (rawkey.startsWith(workerPrefix)) {
                propertyStore.remove(rawkey);
            }
        }

        save();
    }

    /**
     * Help method used to set the correct key naming in the global properites
     * @param scope one of GlobalConfiguration.SCOPE_ constants
     * @param key the key value
     * @return the raw key value to store in the property file.
     */
    private String propertyKeyHelper(String scope, String key) {
        String retval = null;
        String tempKey = key.toUpperCase();

        if (scope.equals(GlobalConfiguration.SCOPE_NODE)) {
            retval = GlobalConfiguration.SCOPE_NODE + WorkerConfig.getNodeId() + "." + tempKey;
        } else {
            if (scope.equals(GlobalConfiguration.SCOPE_GLOBAL)) {
                retval = GlobalConfiguration.SCOPE_GLOBAL + tempKey;
            } else {
                LOG.error("Error : Invalid scope " + scope);
            }
        }
        return retval;
    }
}
