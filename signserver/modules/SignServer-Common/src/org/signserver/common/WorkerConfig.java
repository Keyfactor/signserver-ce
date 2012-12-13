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
import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.ejbca.core.model.UpgradeableDataHashMap;

/**
 * Class representing a signer config. contains to types of data, 
 * signerproperties that can be both signer and signertoken specific and
 * a collection of clients authorized to use the signer.
 * 
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class WorkerConfig extends UpgradeableDataHashMap {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(WorkerConfig.class);
    
    private static final float LATEST_VERSION = 2;
    /**
     * Environment variable pointing to the node id.
     */
    private static final String NODEID_ENVVAR = "SIGNSERVER_NODEID";
    
    // Constants that can be used to configure a Signer
    public static final String SIGNERPROPERTY_SIGNATUREALGORITHM = ".signaturealgorithm";
    public static final String PROPERTY_AUTHTYPE = "AUTHTYPE";
    
    /**
     * Constants used to specify the authtype for a signer
     */
    public static final String AUTHTYPE_CLIENTCERT = "CLIENTCERT";
    public static final String AUTHTYPE_NOAUTH = "NOAUTH";
    
    /**
     *  PrimeCardHSM Specific Property specifiyng which key to use one the card for signing.
     *  Should be a hash of the public key created when creating the card.
     */
    public static final String PRIMECARDHSMPROPERTY_SIGNERKEY = "defaultKey";
    
    private static final long serialVersionUID = 1L;
    
    protected static final String PROPERTIES = "PROPERTIES";
    
    public static final String CLASS = "CLASSPATH";

    private static String nodeId = null;
    
    @SuppressWarnings("unchecked")
    public WorkerConfig() {
        data.put(PROPERTIES, new Properties());
    }

    /**
     * Method that adds a property to the signer.
     * 
     * @param key
     * @param value
     * @see java.util.Properties
     */
    public void setProperty(String key, String value) {
        ((Properties) data.get(PROPERTIES)).setProperty(key, value);
    }

    /**
     * Method that removes a property from the signer.
     * 
     * @param key
     * @return true if the property was removed, false if it property didn't exist.
     * @see java.util.Properties
     */
    public boolean removeProperty(String key) {
        return (((Properties) data.get(PROPERTIES)).remove(key) != null);
    }

    /**
     * Returns all the workers properties.
     * @return the workers properties.
     */
    public Properties getProperties() {
        return ((Properties) data.get(PROPERTIES));
    }

    /**
     * Returns the specific property from the configuration
     * @return the value corresponding to that property.
     */
    public String getProperty(String key) {
        return ((Properties) data.get(PROPERTIES)).getProperty(key);
    }

    /**
     * Returns the specific property from the configuration with a defaultValue option
     * @return the value corresponding to that property.
     */
    public String getProperty(String key, String defaultValue) {
        return ((Properties) data.get(PROPERTIES)).getProperty(key, defaultValue);
    }

    /**
     * Special method to ge access to the complete data field
     */
    HashMap<Object, Object> getData() {
        return data;
    }

    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    @SuppressWarnings("unchecked")
    public void upgrade() {
        if (data.get(WorkerConfig.CLASS) == null) {
            data.put(WorkerConfig.CLASS, this.getClass().getName());
        }

        data.put(WorkerConfig.VERSION, new Float(LATEST_VERSION));
    }

    /**
     * @return Method retrieving the Node id from the SIGNSERVER_NODEID environment
     * variable
     * 
     */
    public static String getNodeId() {
        if (nodeId == null) {
            nodeId = System.getenv(NODEID_ENVVAR);
            if (nodeId != null) {
                nodeId = nodeId.toUpperCase();
            }

            if (nodeId == null) {
                File confFile = new File(getSignServerConfigFile());
                if (confFile.exists() && confFile.isFile() && confFile.canRead()) {
                    try {
                        nodeId = SignServerUtil.readValueFromConfigFile("signserver_nodeid", confFile);
                    } catch (IOException e) {
                        LOG.error("Error reading node id from signserver configuration file '" + getSignServerConfigFile() + "' : " + e.getMessage());
                    }
                }
            }

            if (nodeId == null) {
                LOG.error("Error, required environment variable " + NODEID_ENVVAR + " isn't set.");
            }
        }

        return nodeId;
    }
    
    public Map<String, String> diff(final WorkerConfig newConfig) {
        Map<Object, Object> newMap = (Map<Object, Object>) newConfig.saveData();
        Map<Object, Object> diff = diffMaps(data, newMap);
        Map<String, String> result = new HashMap<String, String>();

        for (final Object key : diff.keySet()) {
            result.put((String) key, (String) diff.get(key));
        }
        
        return result;
    }
    
    public static Map<String, String> propertyDiff(final WorkerConfig oldConfig,
            final WorkerConfig newConfig) {
        final Map<String, String> result = new HashMap<String, String>();
        final Properties oldProps = oldConfig.getProperties();
        final Properties newProps = newConfig.getProperties();
        
        for (final Object o : newProps.keySet()) {
            final String prop = (String) o;
            final String val = (String) newProps.get(prop);
            
            if (oldProps.containsKey(prop)) {
                if (!val.equals(oldProps.get(prop))) {
                    result.put("changed:" + prop, val);
                }
            } else {
                result.put("added:" + prop, val);
            }
        }
        
        for (final Object o : oldProps.keySet()) {
            final String prop = (String) o;
            final String val = (String) oldProps.get(prop);

            if (!newProps.containsKey(prop)) {
                result.put("removed:" + prop, val);
            }
        }
        
        return result;
    }

    
    /** Create a Map with the differences between the two input objects.
     * Puts the result in a new Map with keys:
     * <pre>
     * changed:key, changedvalue
     * remove:key, removedvalue
     * added:key, addedvalue
     * </pre>
     * 
     * @param oldmap
     * @param newmap
     * @return Map<String, String> with difference
     */
     public static Map<Object, Object> diffMaps(Map<Object, Object> oldmap, Map<Object, Object> newmap) {
        Map<Object, Object> result = new LinkedHashMap<Object, Object>();
        for (Object key : oldmap.keySet()) {
            if (newmap.containsKey(key)) {
                // Check if the value is the same
                Object value = oldmap.get(key);
                if (value == null) {
                    if (newmap.get(key) != null) {
                        result.put("addedvalue:"+key, newmap.get(key));                                         
                    }
                } else if (!value.equals(newmap.get(key))) {
                    Object val = newmap.get(key);
                    if (val == null) {
                        val = ""; 
                    }
                    result.put("changed:"+key, getVal(val));
               }
            } else {
                // Value removed
                Object val = oldmap.get(key);
                if (val == null) {
                        val = ""; 
                }
                result.put("removed:"+key, getVal(val));
            }
        }
        // look for added properties
        for (Object key : newmap.keySet()) {
            if (!oldmap.containsKey(key)) {
                Object val = newmap.get(key);
                if (val == null) {
                        val = ""; 
                }
                result.put("added:"+key, getVal(val));                  
            }
        }
        return result;
    }
     
     /** helper method to get nice output from types that do 
      * not work nicely with Object.toString()
      */
     private static String getVal(Object o) {
         StringBuilder b = new StringBuilder();
         if (o instanceof String[]) {
             b.append('[');
         String[] arr = (String[]) o;
         for (String s: arr) {
             if (b.length() > 1) {
                 b.append(", ");
             }
             b.append(s); 
         }
         b.append(']');
     } else {
         b.append(o);
     }
         return b.toString();
     }

    private static String getSignServerConfigFile() {
        String configFile = CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.SIGNSERVER_CONFIGFILE);
        if (configFile == null || configFile.isEmpty()) {
            configFile = "/etc/signserver/signserver.conf";
        }
        return configFile;
    }
}
