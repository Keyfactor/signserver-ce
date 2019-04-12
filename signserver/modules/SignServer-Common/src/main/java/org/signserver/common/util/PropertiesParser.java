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

import org.bouncycastle.util.encoders.Base64;
import java.util.*;
import org.apache.commons.lang.StringUtils;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.CertificateMatchingRule;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.MatchIssuerWithType;
import org.signserver.common.MatchSubjectWithType;
import org.signserver.common.WorkerConfig;
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
        private final String scope;
        private final String key;
        
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

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((key == null) ? 0 : key.hashCode());
            result = prime * result + ((scope == null) ? 0 : scope.hashCode());
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            GlobalProperty other = (GlobalProperty) obj;
            if (key == null) {
                if (other.key != null)
                    return false;
            } else if (!key.equals(other.key))
                return false;
            if (scope == null) {
                if (other.scope != null)
                    return false;
            } else if (!scope.equals(other.scope))
                return false;
            return true;
        }
    }
    
    /**
     * Representation of a worker property.
     * This only represents the identity of the property, not the actual property value (instance).
     *
     */
    public static class WorkerProperty {
        private final String workerIdOrName;
        private final String key;
        
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

        @Override
        public int hashCode() {
            int hash = 5;
            hash = 67 * hash + (this.workerIdOrName != null ? this.workerIdOrName.hashCode() : 0);
            hash = 67 * hash + (this.key != null ? this.key.hashCode() : 0);
            return hash;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            final WorkerProperty other = (WorkerProperty) obj;
            if ((this.workerIdOrName == null) ? (other.workerIdOrName != null) : !this.workerIdOrName.equals(other.workerIdOrName)) {
                return false;
            }
            if ((this.key == null) ? (other.key != null) : !this.key.equals(other.key)) {
                return false;
            }
            return true;
        }


    }
    
    private final List<String> errors = new LinkedList<>();
    private final List<String> messages = new LinkedList<>();
    private final List<String> workerNames = new ArrayList<>();  
    private final List<String> workerIds = new ArrayList<>();
    private final Map<GlobalProperty, String> setGlobalProperties = new HashMap<>();
    private final List<GlobalProperty> removeGlobalProperties = new LinkedList<>();
    private final Map<WorkerProperty, String> setWorkerProperties = new HashMap<>();
    private final List<WorkerProperty> removeWorkerProperties = new LinkedList<>();
    
    private final Map<String, List<AuthorizedClient>> addAuthorizedClients = new HashMap<>();
    private final Map<String, List<AuthorizedClient>> removeAuthorizedClients = new HashMap<>();
    
    private final Map<String, List<CertificateMatchingRule>> addAuthorizedClientsGen2 = new HashMap<>();
    private final Map<String, List<CertificateMatchingRule>> removeAuthorizedClientsGen2 = new HashMap<>();
    
    private final Map<String, byte[]> signerCertificates = new HashMap<>();
    private final Map<String, List<byte[]>> signerCertificateChains = new HashMap<>();
    
    private final Map<String, AuthClientEntry> addAuthClientGen2EntryMap = new HashMap<>();
    private final Map<String, AuthClientEntry> removeAuthClientGen2EntryMap = new HashMap<>();

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

        // Process Gen2 auth client rules if exist
        processGen2AuthClientRules(addAuthClientGen2EntryMap, true);
        processGen2AuthClientRules(removeAuthClientGen2EntryMap, false);
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
        
        // For backwards compatibility: If the old global config property for IMPLEMENTATION_CLASS is specified, we also set the new property
        // Note: this logic is somewhat duplicated in SetPropertiesHelper
        if (key.startsWith(WORKER_PREFIX)) {
            String strippedKey = key.substring(WORKER_PREFIX.length());
            String workerId = strippedKey.substring(0, strippedKey.indexOf('.'));
             
            if (key.endsWith(".SIGNERTOKEN.CLASSPATH")) {
                setWorkerProperty(workerId, CRYPTOTOKEN_IMPLEMENTATION_CLASS, value);
            } else if (key.endsWith(".CLASSPATH")) {
                setWorkerProperty(workerId, IMPLEMENTATION_CLASS, value);
                setWorkerProperty(workerId, WorkerConfig.TYPE, ""); // Empty type so it will be auto-detected
            }
        }
    }

    private void removeGlobalProperty(String scope, String key) {
        messages.add("Removing the global property " + key + " with scope " + scope);
        removeGlobalProperties.add(new GlobalProperty(scope, key));
    }
    
    private <T> void addWorkerDataToList(final Map<String, List<T>> map, final String workerIdOrName, final T data) {
        List<T> datas = map.get(workerIdOrName);
        
        if (datas == null) {
            datas = new LinkedList<>();
            map.put(workerIdOrName, datas);
        }
        
        datas.add(data);
    }
    
    private void addAuthorizedClient(final String workerIdOrName, final AuthorizedClient ac) {
        addWorkerDataToList(addAuthorizedClients, workerIdOrName, ac);
    }
    
    private void addAuthorizedClientGen2(final String workerIdOrName, final CertificateMatchingRule ac) {
        addWorkerDataToList(addAuthorizedClientsGen2, workerIdOrName, ac);
    }
    
    private void removeAuthorizedClient(final String workerIdOrName, final AuthorizedClient ac) {
        addWorkerDataToList(removeAuthorizedClients, workerIdOrName, ac);
    }
    
    private void removeAuthorizedClientGen2(final String workerIdOrName, final CertificateMatchingRule ac) {
        addWorkerDataToList(removeAuthorizedClientsGen2, workerIdOrName, ac);
    }

    private void setWorkerProperty(final String workerIdOrName, String propertykey, String propertyvalue) {
        if (propertykey.startsWith(AUTHCLIENT)) {

            if (propertykey.endsWith(AUTHORIZED_CLIENTS_DOT_TYPE) || propertykey.endsWith(AUTHORIZED_CLIENTS_DOT_VALUE)
                    || propertykey.endsWith(AUTHORIZED_CLIENTS_DOT_DESCRIPTION)) {
                // This is new format auth client so do it new way
                populateGen2AuthClientEntries(workerIdOrName, propertykey, propertyvalue, true);
            } else { // This is legacy auth client so do it old way
                String values[] = propertyvalue.split(";");
                AuthorizedClient ac = new AuthorizedClient(values[0], values[1]);
                messages.add("Adding Authorized Client with certificate serial " + ac.getCertSN() + " and issuer DN " + ac.getIssuerDN() + " to " + propertyvalue + " for worker " + workerIdOrName);
                addAuthorizedClient(workerIdOrName, ac);
            }
        } else {
            if (propertykey.startsWith(DOT_SIGNERCERTIFICATE.substring(1))) {
                signerCertificates.put(workerIdOrName, Base64.decode(propertyvalue.getBytes()));
            } else {
                if (propertykey.startsWith(DOT_SIGNERCERTCHAIN.substring(1))) {
                    String certs[] = propertyvalue.split(";");
                    ArrayList<byte[]> chain = new ArrayList<>();
                    for (String base64cert : certs) {
                        if (!base64cert.trim().isEmpty()) {
                            byte[] cert = Base64.decode(base64cert.getBytes());
                            chain.add(cert);
                        }
                    }
                    signerCertificateChains.put(workerIdOrName, chain);
                } else {
                    if (propertykey.equals(PropertiesConstants.NAME)) {
                        workerIds.add(workerIdOrName);
                        workerNames.add(propertyvalue);
                    }
                    messages.add("Setting the property " + propertykey + " to " + propertyvalue + " for worker " + workerIdOrName);
                    setWorkerProperties.put(new WorkerProperty(workerIdOrName, propertykey), propertyvalue);
                }
            }
        }
    }

    private void removeWorkerProperty(final String workerIdOrName, String propertykey, String propertyvalue) {
        if (propertykey.startsWith(AUTHCLIENT)) {
            if (propertykey.endsWith(AUTHORIZED_CLIENTS_DOT_TYPE) || propertykey.endsWith(AUTHORIZED_CLIENTS_DOT_VALUE)) {
                // This is new format auth client so do it new way
                populateGen2AuthClientEntries(workerIdOrName, propertykey, propertyvalue, false);
            } else { // This is legacy auth client so do it old way
                String values[] = propertyvalue.split(";");
                AuthorizedClient ac = new AuthorizedClient(values[0], values[1]);
                messages.add("Removing authorized client with certificate serial " + ac.getCertSN() + " and issuer DN " + ac.getIssuerDN() + " from " + propertyvalue + " for worker " + workerIdOrName);
                removeAuthorizedClient(workerIdOrName, ac);
            }
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
    
    private void processGen2AuthClientRules(Map<String, AuthClientEntry> authClientGen2EntryMap, boolean add) {
        Iterator it = authClientGen2EntryMap.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, AuthClientEntry> pair = (Map.Entry) it.next();
            String seqNO = pair.getKey();
            AuthClientEntry entry = pair.getValue();
            CertificateMatchingRule rule = entry.getRule();
            if (allMandatoryFieldsExistInProvidedRule(rule)) {
                if (StringUtils.isBlank(rule.getDescription())) {
                    rule.setDescription("Imported rule");
                }
                String workerIdOrName = entry.getWorkerIdOrName();
                if (add) {
                    addAuthorizedClientGen2(workerIdOrName, rule);
                    messages.add("Adding Authorized Client with rule " + rule.toString() + " for worker " + workerIdOrName);
                } else {
                    messages.add("Removing Authorized Client with rule " + rule.toString() + " for worker " + workerIdOrName);
                    removeAuthorizedClientGen2(workerIdOrName, rule);
                }
            } else {
                errors.add("Either all mandatory fields are not provided or same prefix is not provided for " + AUTHCLIENT + " " + seqNO);
                break;
            }
            it.remove();
        }
    }
    
    private void populateGen2AuthClientEntries(String workerIdOrName, String propertykey, String propertyvalue, boolean add) {
        int authClientLength = AUTHCLIENT.length();
        String clientRuleSeq = propertykey.substring(authClientLength, authClientLength + 1);
        if (clientRuleSeq.equals(".")) {  // In case AUTHCLIENT.SUBJECT.VALUE instead of AUTHCLIENT1.SUBJECT.VALUE
            clientRuleSeq = "";
            authClientLength = authClientLength - 1;
        }

        AuthClientEntry entry;
        if (add) {
            entry = addAuthClientGen2EntryMap.get(clientRuleSeq);
            if (entry == null) {
                entry = new AuthClientEntry(new CertificateMatchingRule(), workerIdOrName);
                addAuthClientGen2EntryMap.put(clientRuleSeq, entry);
            }
        } else {
            entry = removeAuthClientGen2EntryMap.get(clientRuleSeq);
            if (entry == null) {
                entry = new AuthClientEntry(new CertificateMatchingRule(), workerIdOrName);
                removeAuthClientGen2EntryMap.put(clientRuleSeq, entry);
            }
        }

        String authClientRuleProperty = propertykey.substring(authClientLength + 1);
        switch (authClientRuleProperty) {
            case AUTHORIZED_CLIENTS_DOT_SUBJECT_DOT_TYPE:
                entry.getRule().setMatchSubjectWithType(MatchSubjectWithType.valueOf(propertyvalue));
                break;
            case AUTHORIZED_CLIENTS_DOT_SUBJECT_DOT_VALUE:
                entry.getRule().setMatchSubjectWithValue(propertyvalue);
                break;
            case AUTHORIZED_CLIENTS_DOT_ISSUER_DOT_TYPE:
                entry.getRule().setMatchIssuerWithType(MatchIssuerWithType.valueOf(propertyvalue));
                break;
            case AUTHORIZED_CLIENTS_DOT_ISSUER_DOT_VALUE:
                entry.getRule().setMatchIssuerWithValue(propertyvalue);
                break;
            case AUTHORIZED_CLIENTS_DOT_DESCRIPTION:
                entry.getRule().setDescription(propertyvalue);
                break;
        }
    }
    
    private boolean allMandatoryFieldsExistInProvidedRule(CertificateMatchingRule rule) {
        return rule.getMatchSubjectWithType() != null && rule.getMatchIssuerWithType() != null && rule.getMatchSubjectWithValue() != null
                && rule.getMatchIssuerWithValue() != null;
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
    
    public Map<String, List<CertificateMatchingRule>> getAddAuthorizedClientsGen2() {
        return addAuthorizedClientsGen2;
    }
    
    public Map<String, List<AuthorizedClient>> getRemoveAuthorizedClients() {
        return removeAuthorizedClients;
    }
    
    public Map<String, List<CertificateMatchingRule>> getRemoveAuthorizedClientsGen2() {
        return removeAuthorizedClientsGen2;
    }
    
    public List<String> getWorkerNames() {
        return workerNames;
    }

    public List<String> getWorkerIds() {
        return workerIds;
    }

    private static class AuthClientEntry {

        private CertificateMatchingRule rule;
        private String workerIdOrName;

        public AuthClientEntry(CertificateMatchingRule rule, String workerIdOrName) {
            this.rule = rule;
            this.workerIdOrName = workerIdOrName;
        }

        public AuthClientEntry() {
        }

        public CertificateMatchingRule getRule() {
            return rule;
        }

        public void setRule(CertificateMatchingRule rule) {
            this.rule = rule;
        }

        public String getWorkerIdOrName() {
            return workerIdOrName;
        }

        public void setWorkerIdOrName(String workerIdOrName) {
            this.workerIdOrName = workerIdOrName;
        }
    }
}
