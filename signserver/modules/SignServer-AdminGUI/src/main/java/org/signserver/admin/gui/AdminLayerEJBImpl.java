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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import javax.naming.NamingException;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import org.apache.log4j.Logger;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.audit.SecurityEventsAuditorSessionRemote;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.query.Criteria;
import org.cesecore.util.query.Elem;
import org.cesecore.util.query.QueryCriteria;
import org.cesecore.util.query.clauses.Order;
import org.cesecore.util.query.elems.RelationalOperator;
import org.cesecore.util.query.elems.Term;
import org.signserver.admin.gui.adminws.gen.AdminNotAuthorizedException;
import org.signserver.admin.gui.adminws.gen.AdminNotAuthorizedException_Exception;
import org.signserver.admin.gui.adminws.gen.AdminWS;
import org.signserver.admin.gui.adminws.gen.ArchiveEntry;
import org.signserver.admin.gui.adminws.gen.AuthorizedClient;
import org.signserver.admin.gui.adminws.gen.Base64SignerCertReqData;
import org.signserver.admin.gui.adminws.gen.CryptoTokenAuthenticationFailureException_Exception;
import org.signserver.admin.gui.adminws.gen.CryptoTokenOfflineException_Exception;
import org.signserver.admin.gui.adminws.gen.EventStatus;
import org.signserver.admin.gui.adminws.gen.IllegalRequestException_Exception;
import org.signserver.admin.gui.adminws.gen.InvalidWorkerIdException_Exception;
import org.signserver.admin.gui.adminws.gen.KeyStoreException_Exception;
import org.signserver.admin.gui.adminws.gen.KeyTestResult;
import org.signserver.admin.gui.adminws.gen.LogEntry;
import org.signserver.admin.gui.adminws.gen.LogEntry.AdditionalDetails;
import org.signserver.admin.gui.adminws.gen.Pkcs10CertReqInfo;
import org.signserver.admin.gui.adminws.gen.QueryCondition;
import org.signserver.admin.gui.adminws.gen.QueryOrdering;
import org.signserver.admin.gui.adminws.gen.ResyncException_Exception;
import org.signserver.admin.gui.adminws.gen.SignServerException_Exception;
import org.signserver.admin.gui.adminws.gen.WsGlobalConfiguration;
import org.signserver.admin.gui.adminws.gen.WsWorkerConfig;
import org.signserver.admin.gui.adminws.gen.WsWorkerStatus;
import org.signserver.common.ArchiveMetadata;
import org.signserver.common.CESeCoreModules;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ICertReqData;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.ProcessRequest;
import org.signserver.common.RequestAndResponseManager;
import org.signserver.common.RequestContext;
import org.signserver.common.ResyncException;
import org.signserver.common.ServiceLocator;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerStatus;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;

/**
 * Implementation of the AdminWS interface but using EJB calls.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class AdminLayerEJBImpl implements AdminWS {
    private static final Logger LOG = Logger.getLogger(AdminLayerEJBImpl.class);

    private static final HashSet<String> LONG_COLUMNS = new HashSet<String>();
    
    static {
        LONG_COLUMNS.add(AuditLogEntry.FIELD_TIMESTAMP);
        LONG_COLUMNS.add(AuditLogEntry.FIELD_SEQUENCENUMBER);
    }
    
    private IWorkerSession.IRemote worker;
    private IGlobalConfigurationSession.IRemote global;
    private SecurityEventsAuditorSessionRemote auditor;

    public AdminLayerEJBImpl() throws NamingException {
        if (worker == null) {
            worker = ServiceLocator.getInstance().lookupRemote(
                    IWorkerSession.IRemote.class);
        }
        if (global == null) {
            global = ServiceLocator.getInstance().lookupRemote(
                    IGlobalConfigurationSession.IRemote.class);
        }
        if (auditor == null) {
            auditor = ServiceLocator.getInstance().lookupRemote(
                    SecurityEventsAuditorSessionRemote.class, CESeCoreModules.CORE);
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
                result.setOk(status.getFatalErrors().isEmpty() ? null : "offline");
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
    @Override
    public void reloadConfiguration(int workerId) {
        worker.reloadConfiguration(workerId);
    }

    /**
     * Method used to activate the signtoken of a signer.
     * Should be called from the command line.
     *
     * @param signerId of the signer
     * @param authenticationCode (PIN) used to activate the token.
     * @throws CryptoTokenOfflineException_Exception
     * @throws CryptoTokenAuthenticationFailureException_Exception
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
        org.signserver.admin.gui.adminws.gen.CryptoTokenOfflineException newEx = new org.signserver.admin.gui.adminws.gen.CryptoTokenOfflineException();
        newEx.setMessage(ex.getMessage());
        return new CryptoTokenOfflineException_Exception(ex.getMessage(), newEx, ex);
    }

    private InvalidWorkerIdException_Exception wrap(InvalidWorkerIdException ex) {
        org.signserver.admin.gui.adminws.gen.InvalidWorkerIdException newEx = new org.signserver.admin.gui.adminws.gen.InvalidWorkerIdException();
        newEx.setMessage(ex.getMessage());
        return new InvalidWorkerIdException_Exception(ex.getMessage(), newEx, ex);
    }

    private CryptoTokenAuthenticationFailureException_Exception wrap(CryptoTokenAuthenticationFailureException ex) {
        org.signserver.admin.gui.adminws.gen.CryptoTokenAuthenticationFailureException newEx = new org.signserver.admin.gui.adminws.gen.CryptoTokenAuthenticationFailureException();
        newEx.setMessage(ex.getMessage());
        return new CryptoTokenAuthenticationFailureException_Exception(ex.getMessage(), newEx, ex);
    }

    private KeyStoreException_Exception wrap(KeyStoreException ex) {
        org.signserver.admin.gui.adminws.gen.KeyStoreException newEx = new org.signserver.admin.gui.adminws.gen.KeyStoreException();
        newEx.setMessage(ex.getMessage());
        return new KeyStoreException_Exception(ex.getMessage(), newEx, ex);
    }

    private ResyncException_Exception wrap(ResyncException ex) {
        org.signserver.admin.gui.adminws.gen.ResyncException newEx = new org.signserver.admin.gui.adminws.gen.ResyncException();
        newEx.setMessage(ex.getMessage());
        return new ResyncException_Exception(ex.getMessage(), newEx, ex);
    }
    
    private SignServerException_Exception wrap(SignServerException ex) {
        org.signserver.admin.gui.adminws.gen.SignServerException newEx = new org.signserver.admin.gui.adminws.gen.SignServerException();
        newEx.setMessage(ex.getMessage());
        return new SignServerException_Exception(ex.getMessage(), newEx, ex);
    }

    private IllegalRequestException_Exception wrap(IllegalRequestException ex) {
        org.signserver.admin.gui.adminws.gen.IllegalRequestException newEx = new org.signserver.admin.gui.adminws.gen.IllegalRequestException();
        newEx.setMessage(ex.getMessage());
        return new IllegalRequestException_Exception(ex.getMessage(), newEx, ex);
    }

    /**
     * Method used to deactivate the signtoken of a signer.
     * Should be called from the command line.
     *
     * @param signerId of the signer
     * @return true if deactivation was successful
     * @throws CryptoTokenOfflineException_Exception
     * @throws CryptoTokenAuthenticationFailureException_Exception
     */
    @Override
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
     * @param workerId
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
    @Override
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
    @Override
    public boolean removeWorkerProperty(
            final int workerId,
            final String key) {
        return worker.removeWorkerProperty(workerId, key);
    }

    /**
     * Method that returns a collection of AuthorizedClient of
     * client certificate sn and issuerid accepted for a given signer.
     *
     * @param workerId
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

     * @param workerId
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
     * @param workerId
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
     * @param explicitEccParameters false should be default and will use
     * NamedCurve encoding of ECC public keys (IETF recommendation), use true
     * to include all parameters explicitly (ICAO ePassport requirement).
     */
    @Override
    public Base64SignerCertReqData getPKCS10CertificateRequest(
            final int signerId,
            final Pkcs10CertReqInfo certReqInfo,
            final boolean explicitEccParameters)
            throws CryptoTokenOfflineException_Exception,
            InvalidWorkerIdException_Exception {
        final Base64SignerCertReqData result;
        try {
            final ICertReqData data = worker.getCertificateRequest(signerId,
                    new PKCS10CertReqInfo(certReqInfo.getSignatureAlgorithm(),
                    certReqInfo.getSubjectDN(), null), explicitEccParameters);
            if (!(data instanceof org.signserver.common.Base64SignerCertReqData)) {
                throw new RuntimeException("Unsupported cert req data: " + data);
            }
            result = new Base64SignerCertReqData();
            result.setBase64CertReq(((org.signserver.common.Base64SignerCertReqData) data).getBase64CertReq());
            return result;
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
            final boolean explicitEccParameters,
            final boolean defaultKey)
                throws CryptoTokenOfflineException_Exception,
                InvalidWorkerIdException_Exception {
        final Base64SignerCertReqData result;
        try {
            final ICertReqData data = worker.getCertificateRequest(signerId, 
                    new PKCS10CertReqInfo(certReqInfo.getSignatureAlgorithm(),
                    certReqInfo.getSubjectDN(), null), explicitEccParameters,
                    defaultKey);
            if (!(data instanceof org.signserver.common.Base64SignerCertReqData)) {
                throw new RuntimeException("Unsupported cert req data: " + data);
            }
            result = new Base64SignerCertReqData();
            result.setBase64CertReq(((org.signserver.common.Base64SignerCertReqData) data).getBase64CertReq());
            return result;
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
     * @throws CryptoTokenOfflineException_Exception In case the crypto token or the worker
     * is not active
     */
    @Override
    public byte[] getSignerCertificate(
            final int signerId)
            throws CryptoTokenOfflineException_Exception {
        try {
            return worker.getSignerCertificateBytes(signerId);
        } catch (CryptoTokenOfflineException ex) {
            throw wrap(ex);
        } catch (RuntimeException ex) {
            // Old version of server
            LOG.info("Assuming old version of server");
            return getSignerCertificateOld(signerId);
        }
    }
    
    public byte[] getSignerCertificateOld(
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
     * @throws CryptoTokenOfflineException_Exception In case the crypto token or the worker
     * is not active
     */
    @Override
    public List<byte[]> getSignerCertificateChain(
            final int signerId)
            throws CryptoTokenOfflineException_Exception {
        try {
            return worker.getSignerCertificateChainBytes(signerId);
        } catch (CryptoTokenOfflineException ex) {
            throw wrap(ex);
        } catch (RuntimeException ex) {
            // Old version of server
            LOG.info("Assuming old version of server");
            return getSignerCertificateChainOld(signerId);
        }
    }
    
    public List<byte[]> getSignerCertificateChainOld(
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
     * @throws CryptoTokenOfflineException_Exception In case the cryptotoken is offline
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
     * @throws CryptoTokenOfflineException_Exception In case the cryptotoken is offline
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

    @Override
    public long getKeyUsageCounterValue(final int workerId) throws
            AdminNotAuthorizedException_Exception,
            CryptoTokenOfflineException_Exception {
        try {
            return worker.getKeyUsageCounterValue(workerId);
        } catch(CryptoTokenOfflineException ex) {
            throw wrap(ex);
        }
    }

    /**
     * Method used to remove a key from a signer.
     *
     * @param signerId id of the signer
     * @param purpose on of ICryptoToken.PURPOSE_ constants
     * @return true if removal was successful.
     * @deprecated No longer used. Use removeKey instead.
     */
    @Override
    @Deprecated
    public boolean destroyKey(final int signerId,
            final int purpose)
            throws InvalidWorkerIdException_Exception {
        return false;
    }
    
    @Override
    public boolean removeKey(int signerId, String alias) throws AdminNotAuthorizedException_Exception, CryptoTokenOfflineException_Exception, InvalidWorkerIdException_Exception, KeyStoreException_Exception, SignServerException_Exception {
        try {
            return worker.removeKey(signerId, alias);
        } catch (CryptoTokenOfflineException ex) {
            throw wrap(ex);
        } catch (InvalidWorkerIdException ex) {
            throw wrap(ex);
        } catch (KeyStoreException ex) {
            throw wrap(ex);
        } catch (SignServerException ex) {
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
     * @throws CryptoTokenOfflineException_Exception
     * @throws KeyStoreException_Exception
     */
    @Override
    @SuppressWarnings("deprecation") // org.signserver.server.KeyTestResult is used for backwards compatibility
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
                } else if (o instanceof org.signserver.common.KeyTestResult) {
                    org.signserver.common.KeyTestResult key
                        = (org.signserver.common.KeyTestResult) o;
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
            worker.uploadSignerCertificate(signerId, signerCert, scope);
        } catch (CertificateException ex) {
            // Log stacktrace and only pass on description to client
            LOG.error("Unable to parse certificate", ex);
            throw new IllegalRequestException_Exception(
                    "Unable to parse certificate", null, ex);
        }
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
            worker.uploadSignerCertificateChain(signerId, signerCerts, scope);
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
    @Override
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
    @Override
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
            result.setClusterClassLoaderEnabled(false);
            result.setRequireSigning(false);
            result.setUseClassVersions(false);
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
    @Override
    public List<Integer> getWorkers(
            final int workerType) {
        return worker.getWorkers(workerType);
    }

    /**
     * Method that is used after a database crash to restore all cached data to
     * database.
     * @throws ResyncException_Exception if resync was unsuccessfull
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

    @Override
    public List<byte[]> process(final String workerIdOrName,
            final List<byte[]> requests)
            throws AdminNotAuthorizedException_Exception,
            CryptoTokenOfflineException_Exception,
            IllegalRequestException_Exception,
            InvalidWorkerIdException_Exception, SignServerException_Exception {
        final List<byte[]> result = new LinkedList<byte[]>();

        final RequestContext requestContext = new RequestContext();

        final int workerId = getWorkerId(workerIdOrName);

        for (byte[] requestBytes : requests) {
            final ProcessRequest req;
            try {
                req = RequestAndResponseManager.parseProcessRequest(
                        requestBytes);
            } catch (IOException ex) {
                LOG.error("Error parsing process request", ex);
                final IllegalRequestException fault
                        = new IllegalRequestException(
                            "Error parsing process request", ex);
                throw wrap(fault);
            }
            try {
                result.add(RequestAndResponseManager.serializeProcessResponse(
                    worker.process(workerId, req, requestContext)));
            } catch (IOException ex) {
                LOG.error("Error serializing process response", ex);
                final IllegalRequestException fault
                        = new IllegalRequestException(
                            "Error serializing process response", ex);
                throw wrap(fault);
            } catch (org.signserver.common.IllegalRequestException ex) {
                throw wrap(ex);
            } catch (CryptoTokenOfflineException ex) {
                throw wrap(ex);
            } catch (SignServerException ex) {
                throw wrap(ex);
            }
        }
        return result;
    }

    @Override
    public List<LogEntry> queryAuditLog(int startIndex, int max, List<QueryCondition> conditions, List<QueryOrdering> ordering) throws AdminNotAuthorizedException_Exception, SignServerException_Exception {
        // For now we only query on of the available audit devices
        Set<String> devices = auditor.getQuerySupportingLogDevices();
        if (devices.isEmpty()) {
            throw wrap(new SignServerException("No log devices available for querying"));
        }
        final String device = devices.iterator().next();

        final List<Elem> elements = toElements(conditions);
        final QueryCriteria qc = QueryCriteria.create();
        
        for (QueryOrdering order : ordering) {
            qc.add(new Order(order.getColumn(), Order.Value.valueOf(order.getOrder().name())));
        }
        
        if (!elements.isEmpty()) {
            qc.add(andAll(elements, 0));
        }
        
        try {
            return toLogEntries(worker.selectAuditLogs(startIndex, max, qc, device));
        } catch (AuthorizationDeniedException ex) {
            throw new AdminNotAuthorizedException_Exception(ex.getMessage(), new AdminNotAuthorizedException());
        }
    }
    
    private List<LogEntry> toLogEntries(final List<? extends AuditLogEntry> entries) {
        final List<LogEntry> results = new LinkedList<LogEntry>();
        for (AuditLogEntry entry : entries) {
            results.add(fromAuditLogEntry(entry));
        }
        return results;
    }
    
    private List<Elem> toElements(List<QueryCondition> conditions) {
        final LinkedList<Elem> results = new LinkedList<Elem>();
        for (QueryCondition cond : conditions) {
            final Object value;
            if (LONG_COLUMNS.contains(cond.getColumn()) 
                    && !cond.getOperator().equals(org.signserver.admin.gui.adminws.gen.RelationalOperator.NULL) 
                    && !cond.getOperator().equals(org.signserver.admin.gui.adminws.gen.RelationalOperator.NOTNULL)) {
                value = Long.parseLong(cond.getValue());
            } else {
                value = cond.getValue();
            }
            results.add(new Term(RelationalOperator.valueOf(cond.getOperator().name()), cond.getColumn(), value));
        }
        return results;
    }
    
    protected Elem andAll(final List<Elem> elements, final int index) {
        if (index >= elements.size() - 1) {
            return elements.get(index);
        } else {
            return Criteria.and(elements.get(index), andAll(elements, index + 1));
        }
    }
    
    public static LogEntry fromAuditLogEntry(final AuditLogEntry src) {
        final LogEntry result = new LogEntry();

        final Map<String, Object> mapAdditionalDetails = src.getMapAdditionalDetails();
        final AdditionalDetails additionalDetails = new LogEntry.AdditionalDetails();
        if (mapAdditionalDetails != null) {
            for (Map.Entry<String, Object> entry : mapAdditionalDetails.entrySet()) {
                AdditionalDetails.Entry dst = new AdditionalDetails.Entry();
                dst.setKey(entry.getKey());
                dst.setValue("" + entry.getValue());
                additionalDetails.getEntry().add(dst);
            }
        }

        result.setTimeStamp(src.getTimeStamp());
        result.setEventType(src.getEventTypeValue().toString());
        result.setEventStatus(EventStatus.fromValue(src.getEventStatusValue().toString()));
        result.setAuthToken(src.getAuthToken());
        result.setServiceType(src.getServiceTypeValue().toString());
        result.setModuleType(src.getModuleTypeValue().toString());
        result.setCustomId(src.getCustomId());
        result.setSearchDetail1(src.getSearchDetail1());
        result.setSearchDetail2(src.getSearchDetail2());
        result.setAdditionalDetails(additionalDetails);
        result.setSequenceNumber(src.getSequenceNumber());
        result.setNodeId(src.getNodeId());
        
        return result;
    }

    @Override
    public List<ArchiveEntry> queryArchive(int startIndex, int max, List<QueryCondition> conditions, List<QueryOrdering> ordering) throws AdminNotAuthorizedException_Exception, SignServerException_Exception {
        final List<Elem> elements = toElements(conditions);
        final QueryCriteria qc = QueryCriteria.create();
        
        for (QueryOrdering order : ordering) {
            qc.add(new Order(order.getColumn(), Order.Value.valueOf(order.getOrder().name())));
        }
        
        if (!elements.isEmpty()) {
            qc.add(andAll(elements, 0));
        }
        
        try {
            return toArchiveEntries(worker.searchArchive(startIndex, max, qc));
        } catch (AuthorizationDeniedException ex) {
            throw new AdminNotAuthorizedException_Exception(ex.getMessage(), new AdminNotAuthorizedException());
        }
    }
    
    private List<ArchiveEntry> toArchiveEntries(final Collection<? extends ArchiveMetadata> entries) {
        final List<ArchiveEntry> results = new LinkedList<ArchiveEntry>();
        
        for (final ArchiveMetadata entry : entries) {
            results.add(fromArchiveMetadata(entry));
        }
        
        return results;
    }

    private ArchiveEntry fromArchiveMetadata(final ArchiveMetadata entry) {
        final ArchiveEntry result = new ArchiveEntry();
        
        result.setArchiveId(entry.getArchiveId());
        result.setRequestCertSerialNumber(entry.getRequestCertSerialNumber());
        result.setRequestIssuerDN(entry.getRequestIssuerDN());
        result.setRequestIP(entry.getRequestIP());
        result.setSignerId(entry.getSignerId());
        result.setTime(entry.getTime().getTime());
        result.setType(entry.getType());
        
        return result;
    }
}
