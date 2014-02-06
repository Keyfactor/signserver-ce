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

import java.util.*;
import org.ejbca.util.Base64;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.GlobalConfiguration;
import static org.signserver.common.util.PropertiesConstants.*;

/**
 * Parser for loading properties.
 * Based on the SetPropertiesHelper implementation in the AdminCLI.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class PropertiesParser {
   
    /**
     * Representation of a global property.
     * This only represents the identity of a property, not the actual property value (instance).
     */
    public static class GlobalProperty {
        private String scope;
        private String key;
        
        public GlobalProperty(final String scope, final String key) {
            this.scope = scope;
            this.key = key;
        }
        
        public String getScope() {
            return scope;
        }
        
        public String getKey() {
            return key;
        }
    }
    
    /**
     * Representation of a worker property.
     * This only represents the identity of the property, not the actual property value (instance).
     *
     */
    public static class WorkerProperty {
        private String workerIdOrName;
        private String key;
        
        public WorkerProperty(final String workerIdOrName, final String key) {
            this.workerIdOrName = workerIdOrName;
            this.key = key;
        }
        
        public String getWorkerIdOrName() {
            return workerIdOrName;
        }
        
        public String getKey() {
            return key;
        }
    }
    
    private List<String> errors = new LinkedList<String>();
    private List<String> messages = new LinkedList<String>();
    private Map<GlobalProperty, String> setGlobalProperties = new HashMap<GlobalProperty, String>();
    private List<GlobalProperty> removeGlobalProperties = new LinkedList<GlobalProperty>();
    private Map<WorkerProperty, String> setWorkerProperties = new HashMap<WorkerProperty, String>();
    private List<WorkerProperty> removeWorkerProperties = new LinkedList<WorkerProperty>();
    
    private Map<String, List<AuthorizedClient>> addAuthorizedClients = new HashMap<String, List<AuthorizedClient>>();
    private Map<String, List<AuthorizedClient>> removeAuthorizedClients = new HashMap<String, List<AuthorizedClient>>();
    
    private Map<String, byte[]> signerCertificates = new HashMap<String, byte[]>();
    private Map<String, List<byte[]>> signerCertificateChains = new HashMap<String, List<byte[]>>();

    /**
     * Parse a set of properties.
     * 
     * @param properties
     */
    public void process(Properties properties) {
        Enumeration<?> iter = properties.keys();
        while (iter.hasMoreElements()) {
            String key = (String) iter.nextElement();
            processKey(key.toUpperCase(), properties.getProperty(key));
        }
    }

    private void processKey(String key, String value) {
        if (isRemoveKey(key)) {
            String newkey = key.substring(REMOVE_PREFIX.length());
            processKey(key, newkey, value, false);
        } else {
            processKey(key, key, value, true);
        }

    }

    private boolean isRemoveKey(String key) {
        return key.startsWith(REMOVE_PREFIX);
    }

    private void processKey(String originalKey, String key, String value, boolean add) {
        if (key.startsWith(GLOBAL_PREFIX_DOT)) {
            String strippedKey = key.substring(GLOBAL_PREFIX_DOT.length());
            processGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL, strippedKey, value, add);
        } else {
            if (key.startsWith(NODE_PREFIX_DOT)) {
                String strippedKey = key.substring(NODE_PREFIX_DOT.length());
                processGlobalProperty(GlobalConfiguration.SCOPE_NODE, strippedKey, value, add);
            } else {
                if (key.startsWith(WORKER_PREFIX)) {
                    String strippedKey = key.substring(WORKER_PREFIX.length());
                    processWorkerProperty(originalKey, strippedKey, value, add);
                } else {
                    if (key.startsWith(OLDWORKER_PREFIX)) {
                        String strippedKey = key.substring(OLDWORKER_PREFIX.length());
                        processWorkerProperty(originalKey, strippedKey, value, add);
                    } else {
                        errors.add("Error in propertyfile syntax, check : " + originalKey);
                    }
                }
            }
        }

    }

    private void processWorkerProperty(String originalKey, String strippedKey, String value, boolean add) {
        String splittedKey = strippedKey.substring(0, strippedKey.indexOf('.'));
        String propertykey = strippedKey.substring(strippedKey.indexOf('.') + 1);

        if (add) {
            setWorkerProperty(splittedKey, propertykey, value);
        } else {
            removeWorkerProperty(splittedKey, propertykey, value);
        }

    }


    private void processGlobalProperty(String scope, String strippedKey, String value, boolean add) {
        if (add) {
            setGlobalProperty(scope, strippedKey, value);
        } else {
            removeGlobalProperty(scope, strippedKey);
        }

    }

    private void setGlobalProperty(String scope, String key, String value) {
        messages.add("Setting the global property " + key + " to " + value + " with scope " + scope);
        setGlobalProperties.put(new GlobalProperty(scope, key), value);
    }

    private void removeGlobalProperty(String scope, String key) {
        messages.add("Removing the global property " + key + " with scope " + scope);
        removeGlobalProperties.add(new GlobalProperty(scope, key));
    }
    
    private <T> void addWorkerDataToList(final Map<String, List<T>> map, final String workerIdOrName, final T data) {
        List<T> datas = map.get(workerIdOrName);
        
        if (datas == null) {
            datas = new LinkedList<T>();
            map.put(workerIdOrName, datas);
        }
        
        datas.add(data);
    }
    
    private void addAuthorizedClient(final String workerIdOrName, final AuthorizedClient ac) {
        addWorkerDataToList(addAuthorizedClients, workerIdOrName, ac);
    }
    
    private void removeAuthorizedClient(final String workerIdOrName, final AuthorizedClient ac) {
        addWorkerDataToList(removeAuthorizedClients, workerIdOrName, ac);
    }

    private void setWorkerProperty(final String workerIdOrName, String propertykey, String propertyvalue) {
        if (propertykey.startsWith(DOT_AUTHCLIENT.substring(1))) {
            String values[] = propertyvalue.split(";");
            AuthorizedClient ac = new AuthorizedClient(values[0], values[1]);
            messages.add("Adding Authorized Client with certificate serial " + ac.getCertSN() + " and issuer DN " + ac.getIssuerDN() + " to " + propertyvalue + " for worker " + workerIdOrName);
            addAuthorizedClient(workerIdOrName, ac);
        } else {
            if (propertykey.startsWith(DOT_SIGNERCERTIFICATE.substring(1))) {
                signerCertificates.put(workerIdOrName, Base64.decode(propertyvalue.getBytes()));
            } else {
                if (propertykey.startsWith(DOT_SIGNERCERTCHAIN.substring(1))) {
                    String certs[] = propertyvalue.split(";");
                    ArrayList<byte[]> chain = new ArrayList<byte[]>();
                    for (String base64cert : certs) {
                        byte[] cert = Base64.decode(base64cert.getBytes());
                        chain.add(cert);
                    }
                    signerCertificateChains.put(workerIdOrName, chain);
                } else {
                    messages.add("Setting the property " + propertykey + " to " + propertyvalue + " for worker " + workerIdOrName);
                    setWorkerProperties.put(new WorkerProperty(workerIdOrName, propertykey), propertyvalue);
                }
            }
        }
    }

    private void removeWorkerProperty(final String workerIdOrName, String propertykey, String propertyvalue) {
        if (propertykey.startsWith(DOT_AUTHCLIENT.substring(1))) {
            String values[] = propertyvalue.split(";");
            AuthorizedClient ac = new AuthorizedClient(values[0], values[1]);
            messages.add("Removing authorized client with certificate serial " + ac.getCertSN() + " and issuer DN " + ac.getIssuerDN() + " from " + propertyvalue + " for worker " + workerIdOrName);
            removeAuthorizedClient(workerIdOrName, ac);
        } else {
            if (propertykey.startsWith(DOT_SIGNERCERTIFICATE.substring(1))) {
                messages.add("Removal of signing certificates isn't supported, skipped.");
            } else {
                if (propertykey.startsWith(DOT_SIGNERCERTCHAIN.substring(1))) {
                    messages.add("Removal of signing certificate chains isn't supported, skipped.");
                } else {
                    messages.add("Removing the property " + propertykey + "  for worker " + workerIdOrName);
                    removeWorkerProperties.add(new WorkerProperty(workerIdOrName, propertykey));
                }
            }
        }
    }

    /**
     * Get list of error messages from parsing.
     * 
     * @return List of errors
     */
    public List<String> getErrors() {
        return errors;
    }
    
    /**
     * Get error status from parsing.
     * 
     * @return true if there was any parsing errors
     */
    public boolean hasErrors() {
        return !errors.isEmpty();
    }
    
    /**
     * Get parser messages (excluding error messages).
     * 
     * @return Messages from the parsing.
     */
    public List<String> getMessages() {
        return messages;
    }
    
    public Map<GlobalProperty, String> getSetGlobalProperties() {
        return setGlobalProperties;
    }
    
    public List<GlobalProperty> getRemoveGlobalProperties() {
        return removeGlobalProperties;
    }
    
    public Map<WorkerProperty, String> getSetWorkerProperties() {
        return setWorkerProperties;
    }
    
    public List<WorkerProperty> getRemoveWorkerProperties() {
        return removeWorkerProperties;
    }
    
    public Map<String, byte[]> getSignerCertificates() {
        return signerCertificates;
    }
    
    public Map<String, List<byte[]>> getSignerCertificateChains() {
        return signerCertificateChains;
    }
    
    public Map<String, List<AuthorizedClient>> getAddAuthorizedClients() {
        return addAuthorizedClients;
    }
    
    public Map<String, List<AuthorizedClient>> getRemoveAuthorizedClients() {
        return removeAuthorizedClients;
    }
}
