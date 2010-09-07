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
package org.signserver.admin.gui;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import java.util.LinkedList;
import java.util.List;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.logging.Level;
import javax.naming.NamingException;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import org.apache.log4j.Logger;
import org.signserver.adminws.AdminWebService;
import org.signserver.adminws.AuthorizedClient;
import org.signserver.adminws.Base64SignerCertReqData;
import org.signserver.adminws.CryptoTokenAuthenticationFailureException_Exception;
import org.signserver.adminws.CryptoTokenOfflineException_Exception;
import org.signserver.adminws.IllegalRequestException_Exception;
import org.signserver.adminws.InvalidWorkerIdException_Exception;
import org.signserver.adminws.KeyStoreException_Exception;
import org.signserver.adminws.KeyTestResult;
import org.signserver.adminws.Pkcs10CertReqInfo;
import org.signserver.adminws.ResyncException_Exception;
import org.signserver.adminws.WsGlobalConfiguration;
import org.signserver.adminws.WsWorkerConfig;
import org.signserver.adminws.WsWorkerStatus;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ICertReqData;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.ResyncException;
import org.signserver.common.ServiceLocator;
import org.signserver.common.WorkerStatus;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;

/**
 *
 * @author markus
 */
public class AdminLayerEJBImpl implements AdminWebService {
    private static final Logger LOG = Logger.getLogger(AdminLayerEJBImpl.class);

    private IWorkerSession.IRemote worker;
    private IGlobalConfigurationSession.IRemote global;

    public AdminLayerEJBImpl() {
        if (worker == null) {
            try {
                worker = ServiceLocator.getInstance().lookupRemote(
                        IWorkerSession.IRemote.class);
            } catch (NamingException ex) {
                LOG.error("Error looking up WorkerSession", ex);
            }
        }
        if (global == null) {
            try {
                global = ServiceLocator.getInstance().lookupRemote(
                        IGlobalConfigurationSession.IRemote.class);
            } catch (NamingException ex) {
                LOG.error("Error looking up GlobalConfigurationSession", ex);
            }
        }
    }

    /**
     * Returns the Id of a worker given a name
     *
     * @param workerName of the worker, cannot be null
     * @return The Id of a named worker or 0 if no such name exists
     */
    @Override
    public int getWorkerId(
            final String workerName) {
        return worker.getWorkerId(workerName);
    }

    /**
     * Returns the current status of a processalbe.
     *
     * Should be used with the cmd-line status command.
     * @param workerId of the signer
     * @return a WorkerStatus class
     */
    @Override
    public WsWorkerStatus getStatus(
            final int workerId)
            throws InvalidWorkerIdException_Exception {
        try {
            final WsWorkerStatus result;
            final WorkerStatus status = worker.getStatus(workerId);
            if (status == null) {
                result = null;
            } else {
                result = new WsWorkerStatus();
                WsWorkerStatus.ActiveConfig activeConfig = new WsWorkerStatus.ActiveConfig();
                for (Entry<Object, Object> pEntry : status.getActiveSignerConfig().getProperties().entrySet()) {
                    WsWorkerStatus.ActiveConfig.Entry entry = new WsWorkerStatus.ActiveConfig.Entry();
                    entry.setKey(pEntry.getKey());
                    entry.setValue(pEntry.getValue());
                    activeConfig.getEntry().add(entry);
                }
                result.setActiveConfig(activeConfig);
                result.setHostname(status.getHostname());
                result.setOk(status.isOK());
                result.setWorkerId(workerId);
                final ByteArrayOutputStream bout1 = new ByteArrayOutputStream();
                status.displayStatus(workerId, new PrintStream(bout1), false);
                result.setStatusText(bout1.toString());
                final ByteArrayOutputStream bout2 = new ByteArrayOutputStream();
                status.displayStatus(workerId, new PrintStream(bout2), true);
                result.setCompleteStatusText(bout2.toString());
            }
            return result;
        } catch (InvalidWorkerIdException ex) {
            throw wrap(ex);
        }
    }


    /**
     * Method used when a configuration have been updated. And should be
     * called from the commandline.
     *
     * @param workerId of the worker that should be reloaded, or 0 to reload
     * reload of all available workers
     */
    public void reloadConfiguration(int workerId) {
        worker.reloadConfiguration(workerId);
    }

    /**
     * Method used to activate the signtoken of a signer.
     * Should be called from the command line.
     *
     * @param signerId of the signer
     * @param authenticationCode (PIN) used to activate the token.
     * @throws CryptoTokenOfflineException
     * @throws CryptoTokenAuthenticationFailureException
     */
    @Override
    public void activateSigner(int signerId,
            String authenticationCode)
            throws CryptoTokenAuthenticationFailureException_Exception,
            CryptoTokenOfflineException_Exception, InvalidWorkerIdException_Exception {
        try {
            worker.activateSigner(signerId, authenticationCode);
        } catch (CryptoTokenAuthenticationFailureException ex) {
            throw wrap(ex);
        } catch (CryptoTokenOfflineException ex) {
            throw wrap(ex);
        } catch (InvalidWorkerIdException ex) {
            throw wrap(ex);
        }
    }

    private CryptoTokenOfflineException_Exception wrap(CryptoTokenOfflineException ex) {
        org.signserver.adminws.CryptoTokenOfflineException newEx = new org.signserver.adminws.CryptoTokenOfflineException();
        newEx.setMessage(ex.getMessage());
        return new CryptoTokenOfflineException_Exception(ex.getMessage(), newEx, ex);
    }

    private InvalidWorkerIdException_Exception wrap(InvalidWorkerIdException ex) {
        org.signserver.adminws.InvalidWorkerIdException newEx = new org.signserver.adminws.InvalidWorkerIdException();
        newEx.setMessage(ex.getMessage());
        return new InvalidWorkerIdException_Exception(ex.getMessage(), newEx, ex);
    }

    private CryptoTokenAuthenticationFailureException_Exception wrap(CryptoTokenAuthenticationFailureException ex) {
        org.signserver.adminws.CryptoTokenAuthenticationFailureException newEx = new org.signserver.adminws.CryptoTokenAuthenticationFailureException();
        newEx.setMessage(ex.getMessage());
        return new CryptoTokenAuthenticationFailureException_Exception(ex.getMessage(), newEx, ex);
    }

    private KeyStoreException_Exception wrap(KeyStoreException ex) {
        org.signserver.adminws.KeyStoreException newEx = new org.signserver.adminws.KeyStoreException();
        newEx.setMessage(ex.getMessage());
        return new KeyStoreException_Exception(ex.getMessage(), newEx, ex);
    }

    private ResyncException_Exception wrap(ResyncException ex) {
        org.signserver.adminws.ResyncException newEx = new org.signserver.adminws.ResyncException();
        newEx.setMessage(ex.getMessage());
        return new ResyncException_Exception(ex.getMessage(), newEx, ex);
    }

    /**
     * Method used to deactivate the signtoken of a signer.
     * Should be called from the command line.
     *
     * @param signerId of the signer
     * @return true if deactivation was successful
     * @throws CryptoTokenOfflineException
     * @throws CryptoTokenAuthenticationFailureException
     */
    public boolean deactivateSigner(int signerId)
                throws CryptoTokenOfflineException_Exception,
            InvalidWorkerIdException_Exception {
        try {
            return worker.deactivateSigner(signerId);
        } catch (CryptoTokenOfflineException ex) {
            throw wrap(ex);
        } catch (InvalidWorkerIdException ex) {
            throw wrap(ex);
        }
    }

/////////////////////////////////////////////////////////////////////////////////

    /**
     * Returns the current configuration of a worker.
     *
     * Observe that this config might not be active until a reload command
     * has been excecuted.
     *
     * @param signerId
     * @return the current (not always active) configuration
     */
    @Override
    public WsWorkerConfig getCurrentWorkerConfig(
            final int workerId) {
        WsWorkerConfig config = new WsWorkerConfig();
        WsWorkerConfig.Properties properties = new WsWorkerConfig.Properties();

        for (Entry<Object, Object> pEntry : worker.getCurrentWorkerConfig(workerId).getProperties().entrySet()) {
            WsWorkerConfig.Properties.Entry entry = new WsWorkerConfig.Properties.Entry();
            entry.setKey(pEntry.getKey());
            entry.setValue(pEntry.getValue());
            properties.getEntry().add(entry);
        }
        config.setProperties(properties);
        return config;
    }

    /**
     * Sets a parameter in a workers configuration.
     *
     * Observe that the worker isn't activated with this config until reload
     * is performed.
     *
     * @param workerId
     * @param key
     * @param value
     */
    public void setWorkerProperty(final int workerId,
            final String key,
            final String value) {
        worker.setWorkerProperty(workerId, key, value);
    }

    /**
     * Removes a given worker's property.
     *
     * @param workerId
     * @param key
     * @return true if the property did exist and was removed othervise false
     */
    public boolean removeWorkerProperty(
            final int workerId,
            final String key) {
        return worker.removeWorkerProperty(workerId, key);
    }

    /**
     * Method that returns a collection of AuthorizedClient of
     * client certificate sn and issuerid accepted for a given signer.
     *
     * @param signerId
     * @return Sorted collection of authorized clients
     */
    @Override
    public List<AuthorizedClient> getAuthorizedClients(
            final int workerId) {
        final Collection<org.signserver.common.AuthorizedClient>
                authorizedClients = worker.getAuthorizedClients(workerId);
        
        final LinkedList<AuthorizedClient> result
                = new LinkedList<AuthorizedClient>();
        for (org.signserver.common.AuthorizedClient client
                : authorizedClients) {
            AuthorizedClient newClient = new AuthorizedClient();
            newClient.setCertSN(client.getCertSN());
            newClient.setIssuerDN(client.getIssuerDN());
            result.add(newClient);
        }

        return result;
    }

    /**
     * Method adding an authorized client to a signer.

     * @param signerId
     * @param authClient
     */
    @Override
    public void addAuthorizedClient(final int workerId,
            final AuthorizedClient authClient) {
        org.signserver.common.AuthorizedClient client
                = new org.signserver.common.AuthorizedClient();
        client.setCertSN(authClient.getCertSN());
        client.setIssuerDN(authClient.getIssuerDN());
        worker.addAuthorizedClient(workerId, client);
    }

    /**
     * Removes an authorized client from a signer.
     *
     * @param signerId
     * @param authClient
     */
    @Override
    public boolean removeAuthorizedClient(
            final int workerId,
            final AuthorizedClient authClient) {
        org.signserver.common.AuthorizedClient client
                = new org.signserver.common.AuthorizedClient();
        client.setCertSN(authClient.getCertSN());
        client.setIssuerDN(authClient.getIssuerDN());
        return worker.removeAuthorizedClient(workerId, client);
    }

    /**
     * Method used to let a signer generate a certificate request
     * using the signers own genCertificateRequest method.
     *
     * @param signerId id of the signer
     * @param certReqInfo information used by the signer to create the request
     */
    @Override
    public Base64SignerCertReqData getPKCS10CertificateRequest(
            final int signerId,
            final Pkcs10CertReqInfo certReqInfo)
            throws CryptoTokenOfflineException_Exception,
            InvalidWorkerIdException_Exception {
        try {
            final ICertReqData data = worker.getCertificateRequest(signerId, 
                    new PKCS10CertReqInfo(certReqInfo.getSignatureAlgorithm(),
                    certReqInfo.getSubjectDN(), null));
            if (!(data instanceof Base64SignerCertReqData)) {
                throw new RuntimeException("Unsupported cert req data");
            }
            return (Base64SignerCertReqData) data;
        } catch (CryptoTokenOfflineException ex) {
            throw wrap(ex);
        } catch (InvalidWorkerIdException ex) {
            throw wrap(ex);
        }
    }

    /**
     * Method used to let a signer generate a certificate request
     * using the signers own genCertificateRequest method.
     *
     * @param signerId id of the signer
     * @param certReqInfo information used by the signer to create the request
     * @param defaultKey true if the default key should be used otherwise for
     * instance use next key.
     */
    @Override
    public Base64SignerCertReqData getPKCS10CertificateRequestForKey(
            final int signerId,
            final Pkcs10CertReqInfo certReqInfo,
            final boolean defaultKey)
                throws CryptoTokenOfflineException_Exception,
                InvalidWorkerIdException_Exception {
        try {
            final ICertReqData data = worker.getCertificateRequest(signerId, 
                    new PKCS10CertReqInfo(certReqInfo.getSignatureAlgorithm(),
                    certReqInfo.getSubjectDN(), null), defaultKey);
            if (!(data instanceof Base64SignerCertReqData)) {
                throw new RuntimeException("Unsupported cert req data");
            }
            return (Base64SignerCertReqData) data;
        } catch (CryptoTokenOfflineException ex) {
            throw wrap(ex);
        } catch (InvalidWorkerIdException ex) {
            throw wrap(ex);
        }
    }

    /**
     * Method returning the current signing certificate for the signer.
     * @param signerId Id of signer
     * @return Current signing certificate if the worker is a signer and it has
     * been configured. Otherwise null or an exception is thrown.
     * @throws CryptoTokenOfflineException In case the crypto token or the worker
     * is not active
     */
    @Override
    public byte[] getSignerCertificate(
            final int signerId)
            throws CryptoTokenOfflineException_Exception {
        try {
            return getEncoded(worker.getSignerCertificate(signerId));
        } catch (CryptoTokenOfflineException ex) {
            throw wrap(ex);
        }
    }

    private byte[] getEncoded(final Certificate certificate) {
        byte[] result = null;
        try {
            if (certificate != null) {
                result = certificate.getEncoded();
            }
        } catch (CertificateEncodingException ex) {
            LOG.error("Certificate encoding error", ex);
        }
        return result;
    }

    /**
     * Method returning the current signing certificate chain for the signer.
     * @param signerId Id of signer
     * @return Current signing certificate chain if the worker is a signer and it
     * has been configured. Otherwise null or an exception is thrown.
     * @throws CryptoTokenOfflineException In case the crypto token or the worker
     * is not active
     */
    @Override
    public List<byte[]> getSignerCertificateChain(
            final int signerId)
            throws CryptoTokenOfflineException_Exception {
        try {
            final List<byte[]> result;
            final List<Certificate> certs = worker.getSignerCertificateChain(signerId);
            if (certs == null) {
                result = null;
            } else {
                result = new LinkedList<byte[]>();
                for (Certificate cert : certs) {
                    result.add(getEncoded(cert));
                }
            }
            return result;
        } catch (CryptoTokenOfflineException ex) {
            throw wrap(ex);
        }
    }

    /**
     * Gets the last date the specified worker can do signings.
     * @param workerId Id of worker to check.
     * @return The last date or null if no last date (=unlimited).
     * @throws CryptoTokenOfflineException In case the cryptotoken is offline
     * for some reason.
     */
    @Override
    public XMLGregorianCalendar getSigningValidityNotAfter(
            final int workerId)
            throws CryptoTokenOfflineException_Exception {
        try {
            final GregorianCalendar c = new GregorianCalendar();
            final Date time = worker.getSigningValidityNotAfter(workerId);
            if (time == null) {
                return null;
            } else {
                c.setTime(time);
                return DatatypeFactory.newInstance().newXMLGregorianCalendar(c);
            }
        } catch (DatatypeConfigurationException ex) {
            throw new CryptoTokenOfflineException_Exception(ex.getMessage(),
                    null, ex);
        } catch (CryptoTokenOfflineException ex) {
            throw wrap(ex);
        }
    }

    /**
     * Gets the first date the specified worker can do signings.
     * @param workerId Id of worker to check.
     * @return The first date or null if no last date (=unlimited).
     * @throws CryptoTokenOfflineException In case the cryptotoken is offline
     * for some reason.
     */
    @Override
    public XMLGregorianCalendar getSigningValidityNotBefore(
            final int workerId)
            throws CryptoTokenOfflineException_Exception {
        try {
            final GregorianCalendar c = new GregorianCalendar();
            final Date time = worker.getSigningValidityNotBefore(workerId);
            if (time == null) {
                return null;
            } else {
                c.setTime(time);
                return DatatypeFactory.newInstance().newXMLGregorianCalendar(c);
            }
        } catch (DatatypeConfigurationException ex) {
            throw new CryptoTokenOfflineException_Exception(ex.getMessage(),
                    null, ex);
        } catch (CryptoTokenOfflineException ex) {
            throw wrap(ex);
        }
    }

    /**
     * Method used to remove a key from a signer.
     *
     * @param signerId id of the signer
     * @param purpose on of ICryptoToken.PURPOSE_ constants
     * @return true if removal was successful.
     */
    @Override
    public boolean destroyKey(final int signerId,
            final int purpose)
            throws InvalidWorkerIdException_Exception {
        try {
            return worker.destroyKey(signerId, purpose);
        } catch (InvalidWorkerIdException ex) {
            throw wrap(ex);
        }
    }

    /**
     * Generate a new keypair.
     * @param signerId Id of signer
     * @param keyAlgorithm Key algorithm
     * @param keySpec Key specification
     * @param alias Name of the new key
     * @param authCode Authorization code
     * @throws CryptoTokenOfflineException
     * @throws IllegalArgumentException
     */
    @Override
    public String generateSignerKey(
            final int signerId,
            final String keyAlgorithm,
            final String keySpec,
            final String alias,
            final String authCode)
            throws CryptoTokenOfflineException_Exception,
            InvalidWorkerIdException_Exception {
        try {
            return worker.generateSignerKey(signerId, keyAlgorithm, keySpec, 
                    alias, authCode.toCharArray());
        } catch (CryptoTokenOfflineException ex) {
            throw wrap(ex);
        } catch (InvalidWorkerIdException ex) {
            throw wrap(ex);
        }
    }

    /**
     * Tests the key identified by alias or all keys if "all" specified.
     *
     * @param signerId Id of signer
     * @param alias Name of key to test or "all" to test all available
     * @param authCode Authorization code
     * @return Collection with test results for each key
     * @throws CryptoTokenOfflineException
     * @throws KeyStoreException
     */
    @Override
    public List<KeyTestResult> testKey(
            final int signerId,
            final String alias,
            final String authCode)
            throws CryptoTokenOfflineException_Exception,
            InvalidWorkerIdException_Exception, KeyStoreException_Exception {
        try {
            final LinkedList<KeyTestResult> results = new LinkedList<KeyTestResult>();
            final Collection<? extends Object> ress
                    = worker.testKey(signerId, alias, authCode.toCharArray());
            for (Object o : ress) {
                final KeyTestResult result = new KeyTestResult();
                
                // Workaround to support both old
                // server.KeyTestResult and the new
                // KeyTestResult
                if (o instanceof org.signserver.server.KeyTestResult) {
                    org.signserver.server.KeyTestResult key
                        = (org.signserver.server.KeyTestResult) o;
                    result.setAlias(key.getAlias());
                    result.setSuccess(key.isSuccess());
                    result.setPublicKeyHash(key.getPublicKeyHash());
                    result.setStatus(key.getStatus());
                } else {
                    KeyTestResult key
                            = (KeyTestResult) o;
                    result.setAlias(key.getAlias());
                    result.setSuccess(key.isSuccess());
                    result.setPublicKeyHash(key.getPublicKeyHash());
                    result.setStatus(key.getStatus());
                }
                results.add(result);
            }
            return results;
        } catch (CryptoTokenOfflineException ex) {
            throw wrap(ex);
        } catch (InvalidWorkerIdException ex) {
            throw wrap(ex);
        } catch (KeyStoreException ex) {
            throw wrap(ex);
        }
    }

    /**
     * Method used to upload a certificate to a signers active configuration.
     *
     * @param signerId id of the signer
     * @param signerCert the certificate used to sign signature requests
     * @param scope one of GlobalConfiguration.SCOPE_ constants
     */
    @Override
    public void uploadSignerCertificate(
            final int signerId,
            final byte[] signerCert,
            final String scope)
            throws IllegalRequestException_Exception {
        try {
            final X509Certificate cert = getX509Certificate(signerCert);
            worker.uploadSignerCertificate(signerId, cert, scope);
        } catch (CertificateException ex) {
            // Log stacktrace and only pass on description to client
            LOG.error("Unable to parse certificate", ex);
            throw new IllegalRequestException_Exception(
                    "Unable to parse certificate", null, ex);
        }
    }

    private X509Certificate getX509Certificate(byte[] certbytes)
            throws CertificateException {
        final X509Certificate result;
        if (certbytes == null || certbytes.length == 0) {
            result = null;
        } else {
            try {
                final CertificateFactory cf
                        = CertificateFactory.getInstance("X.509", "BC");
                result = (X509Certificate) cf.generateCertificate(
                        new ByteArrayInputStream(certbytes));
            } catch (NoSuchProviderException ex) {
                // Log stacktrace and only pass on description to client
                LOG.error("Error with provider", ex);
                throw new RuntimeException("Internal error");
            }
        }
        return result;
    }

    /**
     * Method used to upload a complete certificate chain to a configuration
     *
     * @param signerId id of the signer
     * @param signerCerts the certificate chain used to sign signature requests
     * @param scope one of GlobalConfiguration.SCOPE_ constants
     */
    @Override
    public void uploadSignerCertificateChain(
            final int signerId,
            final List<byte[]> signerCerts,
            final String scope)
                throws IllegalRequestException_Exception {
        try {
            final List<Certificate> certs = new LinkedList<Certificate>();

            for (byte[] signerCert : signerCerts) {
                final Certificate cert;
                if (signerCert == null || signerCert.length == 0) {
                    cert = null;
                } else {
                    cert = getX509Certificate(signerCert);
                }
                certs.add(cert);
            }
            worker.uploadSignerCertificateChain(signerId, certs, scope);
        } catch (CertificateException ex) {
            // Log stacktrace and only pass on description to client
            LOG.error("Unable to parse certificate", ex);
            throw new IllegalRequestException_Exception(
                    "Unable to parse certificate", null, ex);
        }
    }

    // "Insert Code > Add Web Service Operation")

    /**
     * Method setting a global configuration property. For node. prefix will the
     * node id be appended.
     * @param scope one of the GlobalConfiguration.SCOPE_ constants
     * @param key of the property should not have any scope prefix, never null
     * @param value the value, never null.
     */
    public void setGlobalProperty(
            final String scope,
            final String key,
            final String value) {
        global.setProperty(scope, key, value);
    }

    /**
     * Method used to remove a property from the global configuration.
     * @param scope one of the GlobalConfiguration.SCOPE_ constants
     * @param key of the property should start with either glob. or node.,
     * never null
     * @return true if removal was successful, othervise false.
     */
    public boolean removeGlobalProperty(
            final String scope,
            final String key) {
        return global.removeProperty(scope, key);
    }

    /**
     * Method that returns all the global properties with Global Scope and Node
     * scopes properties for this node.
     * @return A GlobalConfiguration Object, never null
     */
    @Override
    public WsGlobalConfiguration getGlobalConfiguration() {
        final WsGlobalConfiguration result;
        final GlobalConfiguration config = global.getGlobalConfiguration();
        if (config == null) {
            result = null;
        } else {
            result = new WsGlobalConfiguration();
            final WsGlobalConfiguration.Config wConf = new WsGlobalConfiguration.Config();


            final Properties props = new Properties();
            final Enumeration<String> en = config.getKeyEnumeration();
            while (en.hasMoreElements()) {
                final String key = en.nextElement();
                final WsGlobalConfiguration.Config.Entry entry = new WsGlobalConfiguration.Config.Entry();
                entry.setKey(key);
                entry.setValue(config.getProperty(key));
                wConf.getEntry().add(entry);
            }
            result.setConfig(wConf);

            result.setState(config.getState());
            result.setAppVersion(config.getAppVersion());
            result.setClusterClassLoaderEnabled(
                    GlobalConfiguration.isClusterClassLoaderEnabled());
            result.setRequireSigning(GlobalConfiguration.isRequireSigning());
            result.setUseClassVersions(GlobalConfiguration.isUseClassVersions());
        }
        return result;
    }

    /**
     * Help method that returns all worker, either signers or services defined
     * in the global configuration.
     * @param workerType can either be GlobalConfiguration.WORKERTYPE_ALL,
     * _SIGNERS or _SERVICES
     * @return A List if Integers of worker Ids, never null.
     */
    public List<Integer> getWorkers(
            final int workerType) {
        return global.getWorkers(workerType);
    }

    /**
     * Method that is used after a database crash to restore all cached data to
     * database.
     * @throws ResyncException if resync was unsuccessfull
     */
    @Override
    public void globalResync() throws ResyncException_Exception {
        try {
            global.resync();
        } catch (ResyncException ex) {
            wrap(ex);
        }
    }

    /**
     * Method to reload all data from database.
     */
    @Override
    public void globalReload() {
        global.reload();
    }

    private char[] fixAuthCode(List<Integer> _authCode) {
        final char[] result = new char[_authCode.size()];
        int i = 0;
        for (Integer inte : _authCode) {
            result[i++] = (char) inte.intValue();
        }
        return result;
    }

}
