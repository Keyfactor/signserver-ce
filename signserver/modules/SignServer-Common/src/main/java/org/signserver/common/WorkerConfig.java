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
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.internal.UpgradeableDataHashMap;
import static org.signserver.common.util.PropertiesConstants.KEYSTORE_DATA;

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
    
    public static final String PROPERTY_EXPLICITECC = "EXPLICITECC";
    
    /** Worker property: INCLUDE_CERTIFICATE_LEVELS. */
    public static final String PROPERTY_INCLUDE_CERTIFICATE_LEVELS = "INCLUDE_CERTIFICATE_LEVELS";  

    /**
     * Used to override the key alias selector used by a worker.
     */
    public static final String PROPERTY_ALIASSELECTOR = "ALIASSELECTOR";
    
    /**
     * Fully qualified implementation class name for this worker.
     */
    public static final String IMPLEMENTATION_CLASS = "IMPLEMENTATION_CLASS";
    
    /**
     * Fully qualified implementation class name for the crypto token.
     */
    public static final String CRYPTOTOKEN_IMPLEMENTATION_CLASS = "CRYPTOTOKEN_IMPLEMENTATION_CLASS";
    
    /**
     * Type of worker.
     * @see WorkerType
     */
    public static final String TYPE = "TYPE";

    private static String nodeId = null;

    public static final int WORKERTYPE_ALL = 1;
    /** @see WorkerType#TIMED_SERVICE */
    public static final int WORKERTYPE_SERVICES = 3;
    /** @see WorkerType#PROCESSABLE */
    public static final int WORKERTYPE_PROCESSABLE = 2;
    public static final int WORKERTYPE_MAILSIGNERS = 4;
    
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
     * Sets the worker's properties.
     * 
     * @param properties Properties object to set
     */
    public void setProperties(final Properties properties) {
        data.put(PROPERTIES, properties);
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

    @Override
    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    @SuppressWarnings("unchecked")
    @Override
    public void upgrade() {
        if (data.get(WorkerConfig.CLASS) == null) {
            data.put(WorkerConfig.CLASS, this.getClass().getName());
        }

        data.put(WorkerConfig.VERSION, LATEST_VERSION);
    }
    
    public String getImplementationClass() {
        return getProperty(IMPLEMENTATION_CLASS);
    }
    
    public String getCryptoTokenImplementationClass() {
        return getProperty(CRYPTOTOKEN_IMPLEMENTATION_CLASS);
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
       
    /**
     * Compute the difference of properties between two WorkerConfig instances.
     * Puts the result in a new Map with keys:
     * <pre>
     * changed:key, changedvalue
     * removed:key, removedvalue
     * added:key, addedvalue
     * </pre>
     * 
     * @param oldConfig
     * @param newConfig
     * @return Map<String, String> with differences
     */
    public static Map<String, Object> propertyDiff(final WorkerConfig oldConfig,
            final WorkerConfig newConfig) {
        final Map<String, Object> result = new HashMap<>();
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


    private static String getSignServerConfigFile() {
        String configFile = CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.SIGNSERVER_CONFIGFILE);
        if (configFile == null || configFile.isEmpty()) {
            configFile = "/etc/signserver/signserver.conf";
        }
        return configFile;
    }

    /**
     * @return Number of virtual properties that should not be counted as a
     * user-specified properties. Having a worker with less then this number of
     * properties means that it is empty.
     */
    public int getVirtualPropertiesNumber() {
        // NAME and TYPE:
        return 2;
    }
    
    /**
     * Get the keystore data used by the KeystoreInConfigCryptoToken.
     * 
     * @return Keystore data in PKCS#12 format
     */
    public byte[] getKeystoreData() {
        final String keystoreDataString =
                (String) getData().get(KEYSTORE_DATA);
        
        if (keystoreDataString != null) {
            return Base64.decode(keystoreDataString);
        }
        
        return null;
    }
    
    /**
     * Set the keystore data used by the KeystoreInConfigCryptoToken.
     * 
     * @param keystoreData 
     */
    public void setKeystoreData(final byte[] keystoreData) {
        getData().put(KEYSTORE_DATA, new String(Base64.encode(keystoreData)));
    }
}
