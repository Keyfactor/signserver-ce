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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.util.CertTools;
import static org.signserver.common.util.PropertiesConstants.AUTHORIZED_CLIENTS;
import static org.signserver.common.util.PropertiesConstants.AUTHORIZED_CLIENTS_GEN2;
import static org.signserver.common.util.PropertiesConstants.KEYSTORE_DATA;
import static org.signserver.common.util.PropertiesConstants.SIGNERCERT;
import static org.signserver.common.util.PropertiesConstants.SIGNERCERTCHAIN;

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
    
    /**
     * Specifies that no archiving of request data should be done.
     * This implies the worker don't need to retain the request data while
     * the signing operation is in progress.
     */
    public static final String NO_REQUEST_ARCHIVING = "NO_REQUEST_ARCHIVING";
    
    /**
     * Placeholder to use when exporting sensitive worker properties (such as
     * token PIN) in place of the actual value.
     */
    public static final String WORKER_PROPERTY_MASK_PLACEHOLDER = "_MASKED_";

    /**
     * Additional signers that can be referenced by the worker (for instance in order to request crypto instances from).
     */
    public static String OTHER_SIGNERS = "OTHER_SIGNERS";
    
    @SuppressWarnings("unchecked")
    public WorkerConfig() {
        data.put(PROPERTIES, new Properties());
        
        if (get(AUTHORIZED_CLIENTS) == null) {
            put(AUTHORIZED_CLIENTS, new HashSet<AuthorizedClient>());
        }
        
        if (get(AUTHORIZED_CLIENTS_GEN2) == null) {
            put(AUTHORIZED_CLIENTS_GEN2, new HashSet<CertificateMatchingRule>());
        }
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
     * Returns the specific property from the configuration or default value as null if the property isn't set or empty.
     * 
     * @param key Property to get value of
     * @return the value corresponding to that property or default Value as null if unset/empty
     */
    public String getProperty(String key) {
        return getProperty(key, null);
    }
    
    /**
     * Returns the specific property value from the configuration and this value could be empty String.
     * 
     * @param key Property to get value of
     * @return the value corresponding to that property.
     */
    public String getPropertyThatCouldBeEmpty(String key) {
        return ((Properties) data.get(PROPERTIES)).getProperty(key);
    }
    
    /**
     * Returns the specific property value from the configuration with a defaultValue option and this value could be empty String.
     * @param key Property to get value of
     * @param defaultValue Default value, if the property isn't set
     * @return the value corresponding to that property.
     */
    public String getPropertyThatCouldBeEmpty(String key, String defaultValue) {
        return ((Properties) data.get(PROPERTIES)).getProperty(key, defaultValue);
    }

    /**
     * Returns the specific property from the configuration with a defaultValue option.
     * 
     * @param key Property to get value of
     * @param defaultValue Default value, if the property isn't set or empty
     * @return the value corresponding to that property, or defaultValue if unset/empty
     */
    public String getProperty(String key, String defaultValue) {
        String s = ((Properties) data.get(PROPERTIES)).getProperty(key, defaultValue);
        if (s == null || s.trim().isEmpty()) {
            return defaultValue;
        } else {
            return s;
        }
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
     * @deprecated
     * @see propertyDiffAgainst
     */
    public static Map<String, Object> propertyDiff(final WorkerConfig oldConfig,
            final WorkerConfig newConfig) {
        return newConfig.propertyDiffAgainst(oldConfig);
    }
    
    /**
     * Compute the difference of properties between the instance and
     * an older instance.
     * Puts the result in a new Map with keys:
     * <pre>
     * changed:key, changedvalue
     * removed:key, removedvalue
     * added:key, addedvalue
     * </pre>
     * 
     * @param oldConfig
     * @return Map<String, String> with differences
     */
    public Map<String, Object> propertyDiffAgainst(final WorkerConfig oldConfig) {
        final Map<String, Object> result = new HashMap<>();
        final Properties oldProps = oldConfig.getProperties();
        final Properties newProps = getProperties();
        
        final Map<String, String> changed = new HashMap<>();
        final Map<String, String> added = new HashMap<>();
        final Map<String, String> removed = new HashMap<>();
        for (final Object o : newProps.keySet()) {
            final String prop = (String) o;
            final String val = (String) newProps.get(prop);
            
            if (oldProps.containsKey(prop)) {
                if (!val.equals(oldProps.get(prop))) {
                    changed.put(prop, val);
                }
            } else {
                added.put(prop, val);
            }
        }
        
        for (final Object o : oldProps.keySet()) {
            final String prop = (String) o;
            final String val = (String) oldProps.get(prop);

            if (!newProps.containsKey(prop)) {
                removed.put(prop, val);
            }
        }
        
        for (final String key : added.keySet()) {
            if (shouldMaskProperty(key)) {
                result.put("added:" + key, WORKER_PROPERTY_MASK_PLACEHOLDER);
            } else {
                result.put("added:" + key, added.get(key));
            }
        }
        
        for (final String key : changed.keySet()) {
            if (shouldMaskProperty(key)) {
                result.put("changed:" + key, WORKER_PROPERTY_MASK_PLACEHOLDER);
            } else {
                result.put("changed:" + key, changed.get(key));
            }
        }
        
        for (final String key : removed.keySet()) {
            if (shouldMaskProperty(key)) {
                result.put("removed:" + key, WORKER_PROPERTY_MASK_PLACEHOLDER);
            } else {
                result.put("removed:" + key, removed.get(key));
            }
        }

        return result;
    }
    
    /**
     * Determine if a worker property should be masked out in
     * sensitive contexts such as logging and dumping.
     * The list of masked properties are determined at deploy time.
     * Also, properties prefixed or postfixed with a _ is considered as well.
     * 
     * @param propertyName
     * @return True if property should be masked
     */
    public boolean shouldMaskProperty(final String propertyName) {
        final String propertyNameTrimmed =
                StringUtils.removeEnd(StringUtils.removeStart(propertyName, "_"), "_");

        return getMaskedProperties().contains(propertyNameTrimmed.toUpperCase(Locale.ENGLISH));
    }
    
    protected Set<String> getMaskedProperties() {
        return CompileTimeSettings.getInstance().getMaskedProperties();
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
    
    private void put(String key, Serializable value) {
        if (value instanceof String) {
            setProperty(key, (String) value);
        } else {
            getData().put(key, value);
        }
    }

    private Serializable get(String key) {
        final String value = getProperty(key);
        if (value == null) {
            final Object o = getData().get(key);
            if (o instanceof Serializable) {
                return (Serializable) o;
            } else {
                return null;
            }
        }
        return value;
    }
    
    /**
     * Adds a Certificate SN to the collection of authorized clients	  
     * 
     * @param client the AuthorizedClient to add
     */
    @SuppressWarnings("unchecked")
    public void addAuthorizedClient(AuthorizedClient client) {
        ((HashSet<AuthorizedClient>) get(AUTHORIZED_CLIENTS)).add(client);
    }
    
    /**
     * Adds a client to the collection of authorized clients.	  
     * 
     * @param client the AuthorizedClient to add
     */
    @SuppressWarnings("unchecked")
    public void addAuthorizedClientGen2(CertificateMatchingRule client) {
        Serializable o = get(AUTHORIZED_CLIENTS_GEN2);
        if (o == null ) {
            o = new HashSet<CertificateMatchingRule>();
            put(AUTHORIZED_CLIENTS_GEN2, o);
        }
        ((HashSet<CertificateMatchingRule>) o).add(client);
    }
    
    /**
     * Removes a Certificate SN from the collection of authorized clients	  
     * 
     * @param client the AuthorizedClient to remove
     * @return true if the client was found and removed
     */
    @SuppressWarnings("unchecked")
    public boolean removeAuthorizedClient(AuthorizedClient client) {
        final HashSet<AuthorizedClient> authClients =
                (HashSet<AuthorizedClient>) get(AUTHORIZED_CLIENTS);
        
        if (authClients != null) {
            for (final AuthorizedClient authClient : authClients) {
                if (authClient.getCertSN().equals(client.getCertSN()) &&
                    authClient.getIssuerDN().equals(client.getIssuerDN())) {
                    return authClients.remove(authClient);
                }
            }
        }
        
        return false;
    }
    
    /**
     * Removes a client from the collection of authorized clients.
     *
     * @param client the AuthorizedClient to remove
     * @return true if the client was found and removed
     */
    @SuppressWarnings("unchecked")
    public boolean removeAuthorizedClientGen2(CertificateMatchingRule client) {
        boolean matchFoundAndRemoved = false;
        boolean legacyMatchFoundAndRemoved = false;

        final HashSet<CertificateMatchingRule> authClients
                = (HashSet<CertificateMatchingRule>) get(AUTHORIZED_CLIENTS_GEN2);

        if (authClients != null) {
            matchFoundAndRemoved = authClients.remove(client);
        }

        // Check also if this is legacy rule and remove it from legacy structure
        if (client.getMatchSubjectWithType() == MatchSubjectWithType.CERTIFICATE_SERIALNO && client.getMatchIssuerWithType() == MatchIssuerWithType.ISSUER_DN_BCSTYLE) {
            AuthorizedClient legacyClient = new AuthorizedClient(client.getMatchSubjectWithValue(), client.getMatchIssuerWithValue());
            legacyMatchFoundAndRemoved = removeAuthorizedClient(legacyClient);
        }

        return matchFoundAndRemoved || legacyMatchFoundAndRemoved;
    }
    
    /**
     * 	  
     * Gets a collection of authorized client certificates
     * 
     * @return a Collection of String containing the certificate serial number.
     */
    @SuppressWarnings("unchecked")
    public Collection<AuthorizedClient> getAuthorizedClients() {
        final ArrayList<AuthorizedClient> result = new ArrayList<>();
        final HashSet<AuthorizedClient> authClients =
                (HashSet<AuthorizedClient>) get(AUTHORIZED_CLIENTS);
        
        if (authClients != null) {
            for (final AuthorizedClient client : authClients) {
                result.add(client);
            }
        }

        Collections.sort(result);
        return result;
    }
    
    /**
     *
     * Gets a collection of matching rules for authorized client certificates.
     *
     * @return a Collection of matching rules for authorized client certificates.
     */
    @SuppressWarnings("unchecked")
    public Collection<CertificateMatchingRule> getAuthorizedClientsGen2() {
        final ArrayList<CertificateMatchingRule> matchingRules = new ArrayList<>();
        final ArrayList<CertificateMatchingRule> legacyRulesInNewFormat = new ArrayList<>();

        final HashSet<CertificateMatchingRule> authClients
                = (HashSet<CertificateMatchingRule>) get(AUTHORIZED_CLIENTS_GEN2);

        if (authClients != null) {
            authClients.forEach((client) -> {
                matchingRules.add(client);
            });
        }

        Collections.sort(matchingRules);

        // Also check for legacy rules and convert them into new rule structure
        Collection<AuthorizedClient> legacyRules = getAuthorizedClients();
        if (legacyRules != null && !legacyRules.isEmpty()) {
            legacyRules.forEach((legacyRule) -> {
                final BigInteger sn = new BigInteger(legacyRule.getCertSN(), 16);
                String matchSubjectwithValueToBeUsed = sn.toString(16);
                legacyRulesInNewFormat.add(new CertificateMatchingRule(MatchSubjectWithType.CERTIFICATE_SERIALNO, MatchIssuerWithType.ISSUER_DN_BCSTYLE, matchSubjectwithValueToBeUsed, legacyRule.getIssuerDN(), "Legacy rule"));
            });
        }

        if (legacyRulesInNewFormat.isEmpty()) {
            return matchingRules;
        } else {
            ArrayList<CertificateMatchingRule> mergedLegacyAndNewRules = new ArrayList<>();
            mergedLegacyAndNewRules.addAll(legacyRulesInNewFormat);
            mergedLegacyAndNewRules.addAll(matchingRules);
            Collections.sort(mergedLegacyAndNewRules);
            return mergedLegacyAndNewRules;
        }

    }
    
    /**
     * Checks if a certificate is in the list of authorized clients
     * @param clientCertificate
     * @return true if client is authorized.
     */
    @SuppressWarnings("unchecked")
    public boolean isClientAuthorized(X509Certificate clientCertificate) {
        final AuthorizedClient client = new AuthorizedClient(clientCertificate.getSerialNumber().toString(16), clientCertificate.getIssuerDN().toString());
        final HashSet<AuthorizedClient> authClients =
                (HashSet<AuthorizedClient>) get(AUTHORIZED_CLIENTS);

        return authClients != null && authClients.contains(client);
    }
    
    /**
     * Method used to fetch a signers certificate from the config
     * @return the signer certificate stored or null if no certificate have been uploaded.
     * 
     */
    public X509Certificate getSignerCertificate() {
        X509Certificate result = null;
        String stringcert = (String) get(SIGNERCERT);
        if (stringcert == null || stringcert.equals("")) {
            stringcert = (String) get(WorkerConfig.getNodeId() + "." + SIGNERCERT);
        }

        if (stringcert != null && !stringcert.equals("")) {
            Collection<?> certs;
            try {
                certs = CertTools.getCertsFromPEM(new ByteArrayInputStream(stringcert.getBytes()));
                if (certs.size() > 0) {
                    result = (X509Certificate) certs.iterator().next();
                }
            } catch (CertificateException | IllegalStateException e) {
                LOG.error(e);
            }

        }

        if (result == null) {
            // try fetch certificate from certificate chain
            Collection<?> chain = getSignerCertificateChain();
            if (chain != null) {
                Iterator<?> iter = chain.iterator();
                while (iter.hasNext()) {
                    X509Certificate next = (X509Certificate) iter.next();
                    if (next.getBasicConstraints() == -1) {
                        result = next;
                    }
                }
            }
        }
        return result;

    }

    /**
     * Method used to store a signers certificate in the config
     * @param signerCert
     * 
     */
    public void setSignerCertificate(X509Certificate signerCert, String scope) {
        ArrayList<Certificate> list = new ArrayList<>();
        list.add(signerCert);
        if (scope.equals(GlobalConfiguration.SCOPE_GLOBAL)) {
            try {
                String stringcert =
                        new String(CertTools.getPemFromCertificateChain(list));
                put(SIGNERCERT, stringcert);
            } catch (CertificateException e) {
                LOG.error(e);
            }
        } else {
            try {
                String stringcert =
                        new String(CertTools.getPemFromCertificateChain(list));
                put(WorkerConfig.getNodeId() + "." + SIGNERCERT, stringcert);
            } catch (CertificateException e) {
                LOG.error(e);
            }
        }

    }
    
    /**
     * Method used to fetch a signers certificate chain from the config
     * @return the signer certificate stored or null if no certificates have been uploaded.
     * 
     */
    @SuppressWarnings("unchecked")
    public List<Certificate> getSignerCertificateChain() {
        List<Certificate> result = null;
        String stringcert = (String) get(SIGNERCERTCHAIN);
        if (stringcert == null || stringcert.equals("")) {
            stringcert = (String) get(WorkerConfig.getNodeId() + "." + SIGNERCERTCHAIN);
        }

        if (stringcert != null && !stringcert.equals("")) {
            try {
                result = CertTools.getCertsFromPEM(new ByteArrayInputStream(stringcert.getBytes()));
            } catch (CertificateException | IllegalStateException e) {
                LOG.error(e);
            }
        }
        return result;
    }
    
    /**
     * Method used to store a signers certificate chain in the config
     * 
     * @param signerCertificateChain Signer certificate chain to store
     * @param scope Scope (global or node)
     */
    public void setSignerCertificateChain(Collection<Certificate> signerCertificateChain, String scope) {
        if (scope.equals(GlobalConfiguration.SCOPE_GLOBAL)) {
            try {
                String stringcert = new String(CertTools.getPEMFromCerts(signerCertificateChain));
                put(SIGNERCERTCHAIN, stringcert);
            } catch (CertificateException e) {
                LOG.error(e);
            }
        } else {
            try {
                String stringcert = new String(CertTools.getPEMFromCerts(signerCertificateChain));
                put(WorkerConfig.getNodeId() + "." + SIGNERCERTCHAIN, stringcert);
            } catch (CertificateException e) {
                LOG.error(e);
            }
        }
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
