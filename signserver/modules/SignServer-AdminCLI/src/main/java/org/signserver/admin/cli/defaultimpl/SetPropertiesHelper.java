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
package org.signserver.admin.cli.defaultimpl;

import org.bouncycastle.util.encoders.Base64;
import java.io.PrintStream;
import java.rmi.RemoteException;
import java.util.*;
import org.apache.commons.lang.StringUtils;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.CertificateMatchingRule;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.MatchIssuerWithType;
import org.signserver.common.MatchSubjectWithType;
import org.signserver.common.WorkerConfig;
import org.signserver.common.util.PropertiesConstants;
import static org.signserver.common.util.PropertiesConstants.*;

/**
 * Helper class containing methods to parse a set properties file 
 * used from different locations.
 *
 * TODO: Refactor: This feature could be interesting to reuse in other parts of 
 * SignServer as well. Move to SignServer-Common or to a session bean.
 * 
 * @author Philip Vendil 19 maj 2008
 * @version $Id$
 */
public class SetPropertiesHelper {

    private HashMap<String, Integer> genIds = new HashMap<>();
    private PrintStream out;
    private AdminCommandHelper helper = new AdminCommandHelper();
    private List<Integer> workerDeclarations = new ArrayList<>();
    private final Map<String, AuthClientEntry> addAuthClientGen2EntryMap = new HashMap<>();
    private final Map<String, AuthClientEntry> removeAuthClientGen2EntryMap = new HashMap<>();
    private List<AuthClientEntry> addAuthClientGen2Entries = new ArrayList<>();
    private List<AuthClientEntry> removeAuthClientGen2Entries = new ArrayList<>();

    public SetPropertiesHelper(PrintStream out) {
        this.out = out;
    }

    public void process(Properties properties) throws RemoteException, Exception {
        // check first whether worker already exists with provided NAME(s)
        checkWorkerNamesAlreadyExists(properties);
        
        Enumeration<?> iter = properties.keys();
        while (iter.hasMoreElements()) {
            String key = (String) iter.nextElement();
            processKey(key.toUpperCase(), properties.getProperty(key));
        }
        
        // Check if all Gen2 auth client rules valid
        checkAllGen2AuthClientRulesValid(addAuthClientGen2EntryMap, true);
        checkAllGen2AuthClientRulesValid(removeAuthClientGen2EntryMap, false);
        
        // Process all Gen2 auth client rules
        processGen2AuthClientRules();
    }

    public void processKey(String key, String value) throws RemoteException, Exception {
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

    private void processKey(String originalKey, String key, String value, boolean add) throws RemoteException, Exception {
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
                        out.println("Error in propertyfile syntax, check : " + originalKey);
                    }
                }
            }
        }

    }

    private void processWorkerProperty(String originalKey, String strippedKey, String value, boolean add) throws RemoteException, Exception {
        String splittedKey = strippedKey.substring(0, strippedKey.indexOf('.'));
        String propertykey = strippedKey.substring(strippedKey.indexOf('.') + 1);

        final int workerid;
        if (splittedKey.substring(0, 1).matches("\\d")) {
            workerid = Integer.parseInt(splittedKey);

        } else {
            if (splittedKey.startsWith(GENID)) {
                workerid = getGenId(splittedKey);
            } else {
                workerid = helper.getWorkerId(splittedKey);
            }
        }

        if (workerid == 0) {
            out.println("Error in propertyfile syntax, couldn't find worker for key : " + originalKey);
        } else {
            if (add) {
                setWorkerProperty(workerid, propertykey, value);
            } else {
                removeWorkerProperty(workerid, propertykey, value);
            }
        }

    }

    private int getGenId(String splittedKey) throws RemoteException, Exception {
        if (genIds.get(splittedKey) == null) {
            int genid = helper.getWorkerSession().genFreeWorkerId();
            genIds.put(splittedKey, genid);
        }
        return ((Integer) genIds.get(splittedKey));
    }

    private void processGlobalProperty(String scope, String strippedKey, String value, boolean add) throws RemoteException, Exception {
        String key = strippedKey;
        if (strippedKey.startsWith(WORKER_PREFIX + GENID)
                || strippedKey.startsWith(OLDWORKER_PREFIX + GENID)) {
            if (strippedKey.startsWith(WORKER_PREFIX)) {
                strippedKey = strippedKey.substring(WORKER_PREFIX.length());
            }
            if (strippedKey.startsWith(OLDWORKER_PREFIX)) {
                strippedKey = strippedKey.substring(OLDWORKER_PREFIX.length());
            }
            String splittedKey = strippedKey.substring(0, strippedKey.indexOf('.'));
            String propertykey = strippedKey.substring(strippedKey.indexOf('.') + 1);

            if (propertykey.equalsIgnoreCase(GlobalConfiguration.WORKERPROPERTY_CLASSPATH.substring(1))) {
                workerDeclarations.add(getGenId(splittedKey));
            }

            key = WORKER_PREFIX + getGenId(splittedKey) + "." + propertykey;

        } else {
            if (strippedKey.startsWith(WORKER_PREFIX) || strippedKey.startsWith(OLDWORKER_PREFIX)) {
                final String strippedKey2;
                if (strippedKey.startsWith(WORKER_PREFIX)) {
                    strippedKey2 = strippedKey.substring(WORKER_PREFIX.length());
                } else {
                    strippedKey2 = strippedKey.substring(OLDWORKER_PREFIX.length());
                }

                String splittedKey = strippedKey2.substring(0, strippedKey2.indexOf('.'));
                String propertykey = strippedKey2.substring(strippedKey2.indexOf('.') + 1);
                final int workerid;
                if (splittedKey.substring(0, 1).matches("\\d")) {
                    workerid = Integer.parseInt(splittedKey);
                } else {
                    workerid = helper.getWorkerId(splittedKey);
                }

                if (propertykey.equalsIgnoreCase(GlobalConfiguration.WORKERPROPERTY_CLASSPATH.substring(1))) {
                    workerDeclarations.add(workerid);
                }

                key = WORKER_PREFIX + workerid + "." + propertykey;
            }
        }


        if (add) {
            setGlobalProperty(scope, key, value);
        } else {
            removeGlobalProperty(scope, key);
        }

    }

    private void setGlobalProperty(String scope, String key, String value) throws RemoteException, Exception {
        out.println("Setting the global property " + key + " to " + value + " with scope " + scope);
        helper.getGlobalConfigurationSession().setProperty(scope, key, value);

        // For backwards compatibility: If the old global config property for IMPLEMENTATION_CLASS is specified, we also set the new property
        // Note: this logic is somewhat duplicated in PropertiesParser
        if (key.startsWith(WORKER_PREFIX)) {
            String strippedKey = key.substring(WORKER_PREFIX.length());
            String workerIdString = strippedKey.substring(0, strippedKey.indexOf('.'));
             
            // Get worker ID
            final int workerid;
            if (workerIdString.matches("\\d")) {
                workerid = Integer.parseInt(workerIdString);
            } else {
                if (workerIdString.startsWith(GENID)) {
                    workerid = getGenId(workerIdString);
                } else {
                    workerid = helper.getWorkerId(workerIdString);
                }
            }
            if (workerid == 0) {
                out.println("Error in propertyfile syntax, couldn't find worker for key : " + key);
            } else {
                if (key.endsWith(".SIGNERTOKEN.CLASSPATH")) {
                    setWorkerProperty(workerid, CRYPTOTOKEN_IMPLEMENTATION_CLASS, value);
                } else if (key.endsWith(".CLASSPATH")) {
                    setWorkerProperty(workerid, IMPLEMENTATION_CLASS, value);
                    setWorkerProperty(workerid, WorkerConfig.TYPE, ""); // Empty type so it will be auto-detected
                }
            }
        }
    }

    private void removeGlobalProperty(String scope, String key) throws RemoteException, Exception {
        out.println("Removing the global property " + key + " with scope " + scope);
        helper.getGlobalConfigurationSession().removeProperty(scope, key);
    }

    private void setWorkerProperty(int workerId, String propertykey, String propertyvalue) throws RemoteException, Exception {
        if (propertykey.startsWith(AUTHCLIENT)) {

            if (propertykey.endsWith(AUTHORIZED_CLIENTS_DOT_TYPE) || propertykey.endsWith(AUTHORIZED_CLIENTS_DOT_VALUE)
                    || propertykey.endsWith(AUTHORIZED_CLIENTS_DOT_DESCRIPTION)) {
                // This is new format auth client so do it new way
                populateGen2AuthClientEntries(workerId, propertykey, propertyvalue, true);
            } else { // This is legacy auth client so do it old way
                String values[] = propertyvalue.split(";");
                AuthorizedClient ac = new AuthorizedClient(values[0], values[1]);
                out.println("Adding Authorized Client with certificate serial " + ac.getCertSN() + " and issuer DN " + ac.getIssuerDN() + " to " + propertyvalue + " for worker " + workerId);
                helper.getWorkerSession().addAuthorizedClient(workerId, ac);
            }
        } else {
            if (propertykey.startsWith(DOT_SIGNERCERTIFICATE.substring(1))) {
                helper.getWorkerSession().uploadSignerCertificate(workerId, Base64.decode(propertyvalue.getBytes()), GlobalConfiguration.SCOPE_GLOBAL);
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
                    helper.getWorkerSession().uploadSignerCertificateChain(workerId, chain, GlobalConfiguration.SCOPE_GLOBAL);
                } else {
                    out.println("Setting the property " + propertykey + " to " + propertyvalue + " for worker " + workerId);
                    helper.getWorkerSession().setWorkerProperty(workerId, propertykey, propertyvalue);
                }
            }
        }
    }

    private void removeWorkerProperty(int workerId, String propertykey, String propertyvalue) throws RemoteException, Exception {
        if (propertykey.startsWith(AUTHCLIENT)) {

            if (propertykey.endsWith(AUTHORIZED_CLIENTS_DOT_TYPE) || propertykey.endsWith(AUTHORIZED_CLIENTS_DOT_VALUE)
                    || propertykey.endsWith(AUTHORIZED_CLIENTS_DOT_DESCRIPTION)) {
                // This is new format auth client so do it new way
                populateGen2AuthClientEntries(workerId, propertykey, propertyvalue, false);
            } else { // This is legacy auth client so do it old way
                String values[] = propertyvalue.split(";");
                AuthorizedClient ac = new AuthorizedClient(values[0], values[1]);
                out.println("Removing authorized client with certificate serial " + ac.getCertSN() + " and issuer DN " + ac.getIssuerDN() + " from " + propertyvalue + " for worker " + workerId);
                helper.getWorkerSession().removeAuthorizedClient(workerId, ac);
            }
        } else {
            if (propertykey.startsWith(DOT_SIGNERCERTIFICATE.substring(1))) {
                out.println("Removal of signing certificates isn't supported, skipped.");
            } else {
                if (propertykey.startsWith(DOT_SIGNERCERTCHAIN.substring(1))) {
                    out.println("Removal of signing certificate chains isn't supported, skipped.");
                } else {
                    out.println("Removing the property " + propertykey + "  for worker " + workerId);
                    helper.getWorkerSession().removeWorkerProperty(workerId, propertykey);
                }
            }
        }
    }
    
    private void checkAllGen2AuthClientRulesValid(Map<String, AuthClientEntry> authClientGen2EntryMap, boolean add) throws RemoteException, CommandFailureException {
        boolean allRulesValild = true;
        StringBuilder errorMessage = new StringBuilder();
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
                if (add) {
                    addAuthClientGen2Entries.add(entry);
                } else {
                    removeAuthClientGen2Entries.add(entry);
                }
            } else {
                errorMessage.append("Either all mandatory fields are not provided or same prefix is not provided for " + AUTHCLIENT + " ").append(seqNO).append("\n");
                allRulesValild = false;
            }
            it.remove();
        }

        if (!allRulesValild) {
            throw new CommandFailureException(errorMessage.toString());
        }
    }
    
    private void processGen2AuthClientRules() throws RemoteException {
        for (AuthClientEntry entry : addAuthClientGen2Entries) {
            helper.getWorkerSession().addAuthorizedClientGen2(entry.getWorkerId(), entry.getRule());
            out.println("Adding Authorized Client with rule " + entry.getRule().toString() + " for worker " + entry.getWorkerId());
        }
        for (AuthClientEntry entry : removeAuthClientGen2Entries) {
            helper.getWorkerSession().removeAuthorizedClientGen2(entry.getWorkerId(), entry.getRule());
            out.println("Removing Authorized Client with rule " + entry.getRule().toString() + " for worker " + entry.getWorkerId());
        }
    }
    
    private void populateGen2AuthClientEntries(int workerId, String propertykey, String propertyvalue, boolean add) {
        int authClientLength = AUTHCLIENT.length();
        int nextDotIndex = propertykey.indexOf(".");
        String clientRuleSeq = propertykey.substring(authClientLength, nextDotIndex);
        // In case AUTHCLIENT.SUBJECT.VALUE instead of AUTHCLIENT1.SUBJECT.VALUE provided, clientRuleSeq would be empty string ""

        AuthClientEntry entry;
        if (add) {
            entry = addAuthClientGen2EntryMap.get(clientRuleSeq);
            if (entry == null) {
                entry = new AuthClientEntry(new CertificateMatchingRule(), workerId);
                addAuthClientGen2EntryMap.put(clientRuleSeq, entry);
            }
        } else {
            entry = removeAuthClientGen2EntryMap.get(clientRuleSeq);
            if (entry == null) {
                entry = new AuthClientEntry(new CertificateMatchingRule(), workerId);
                removeAuthClientGen2EntryMap.put(clientRuleSeq, entry);
            }
        }

        String authClientRuleProperty = propertykey.substring(authClientLength + clientRuleSeq.length());
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
     * Method that returns a list of all worker declarations that
     * have been sent through this set property helper until now.
     * 
     * @return workerId a list of worker id's.
     */
    public List<Integer> getKeyWorkerDeclarations() {
        return workerDeclarations;
    }
    
    private void checkWorkerNamesAlreadyExists(Properties properties)
            throws RemoteException, CommandFailureException {
        boolean workerWithNameAlreadyExists = false;
        StringBuffer errorMessage = new StringBuffer();
        errorMessage.append("Worker(s) with name already exists:");
        final List<String> workerNames = new ArrayList<>();
        final List<String> workerIds = new ArrayList<>();
        Enumeration<?> iter = properties.keys();
        while (iter.hasMoreElements()) {
            String key = (String) iter.nextElement();
            String value = properties.getProperty(key);
            key = key.toUpperCase();
            if (!isRemoveKey(key) && (key.startsWith(WORKER_PREFIX) || key.startsWith(OLDWORKER_PREFIX))) {
                final int dotIndex = key.indexOf('.');
                String propertykey = key.substring(dotIndex + 1);
                if (propertykey.equals(PropertiesConstants.NAME)) {
                    // extract worker ID part
                    final int prefixLength =
                            key.startsWith(WORKER_PREFIX) ?
                            WORKER_PREFIX.length() : OLDWORKER_PREFIX.length();
                    final String workerId = key.substring(prefixLength, dotIndex);
                    
                    workerIds.add(workerId);
                    workerNames.add(value);
                }
            }
        }
        final List<String> existingWorkerNamesInDB = helper.getWorkerSession().getAllWorkerNames();
        final List<String> alreadyExistingWorkerNames = new ArrayList<String>();
        for (int i = 0; i < workerNames.size(); i++) {
            final String workerName = workerNames.get(i);
            final String workerId = workerIds.get(i);

            if (existingWorkerNamesInDB.contains(workerName)) {
                // check worker ID of existing worker
                try {
                    final String workerIdInDB =
                            String.valueOf(helper.getWorkerSession().getWorkerId(workerName));
                
                    if (!workerIdInDB.equals(workerId)) {
                        workerWithNameAlreadyExists = true;
                        alreadyExistingWorkerNames.add(workerName);
                    }
                } catch (InvalidWorkerIdException e) {
                    /* this shouldn't happen, since we got the list of worker
                     *  names
                     */
                }
            }
        }
        
        // sort already found worker names to keep error message deterministic
        Collections.sort(alreadyExistingWorkerNames);

        alreadyExistingWorkerNames.forEach((name) -> {
            errorMessage.append(" ").append(name);
        });
        
        if (workerWithNameAlreadyExists) {
            throw new CommandFailureException(errorMessage.toString());
        }
    }
    
    private static class AuthClientEntry {

        private CertificateMatchingRule rule;
        private int workerId;

        public AuthClientEntry(CertificateMatchingRule rule, int workerId) {
            this.rule = rule;
            this.workerId = workerId;
        }

        public AuthClientEntry() {
        }

        public CertificateMatchingRule getRule() {
            return rule;
        }

        public void setRule(CertificateMatchingRule rule) {
            this.rule = rule;
        }

        public int getWorkerId() {
            return workerId;
        }

        public void setWorkerIdOrName(int workerId) {
            this.workerId = workerId;
        }
    }
}
