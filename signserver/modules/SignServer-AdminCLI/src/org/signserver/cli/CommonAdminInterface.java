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
package org.signserver.cli;

import java.math.BigInteger;
import java.rmi.RemoteException;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import javax.naming.NamingException;

import org.apache.log4j.Logger;
import org.signserver.common.ArchiveDataVO;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.ResyncException;
import org.signserver.common.ServiceLocator;
import org.signserver.common.SignServerException;
import org.signserver.common.StatusRepositoryData;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IStatusRepositorySession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.common.KeyTestResult;

/**
 * A class that maintains the type of sign server build
 * (SignServer of MailSigner),
 * and directs the CLI calls to the appropriate RMI implementation
 *
 * All calls to the server should go through this class.
 * 
 * FIXME: Refactor away this class it is not needed anymore. Calls can go directly to the session bean instead.
 *
 * @author Philip Vendil 6 okt 2007
 *
 * @version $Id$
 */
public class CommonAdminInterface {

    /** Log4j instance. */
    private static final Logger LOG = Logger.getLogger(
            CommonAdminInterface.class);
    
    /** The global configuration session. */
    private IGlobalConfigurationSession.IRemote globalConfig;

    /** The SignSession. */
    private IWorkerSession.IRemote signsession;
    
    /** The StatusRepositorySession. */
    private IStatusRepositorySession.IRemote statusRepository;

    private String hostname; // TODO: Is the hostname used by any feature?

    public CommonAdminInterface(String hostname) {
        this.hostname = hostname;
    }

    /**
     * @see org.signserver.ejb.WorkerSessionBean#activateSigner(int, String)
     * @see org.signserver.mailsigner.cli.IMailSignerRMI#activateSigner(int, String)
     */
    public void activateSigner(int signerId, String authenticationCode)
            throws CryptoTokenAuthenticationFailureException,
            CryptoTokenOfflineException, InvalidWorkerIdException,
            RemoteException {
        getWorkerSession().activateSigner(signerId, authenticationCode);
    }

    /**
     * @see org.signserver.ejb.WorkerSessionBean#deactivateSigner(int)
     * @see org.signserver.mailsigner.cli.IMailSignerRMI#deactivateSigner(int)
     */
    public boolean deactivateSigner(int signerId)
            throws CryptoTokenOfflineException, InvalidWorkerIdException,
            RemoteException {
        return getWorkerSession().deactivateSigner(signerId);
    }

    /**
     * @see org.signserver.ejb.WorkerSessionBean#destroyKey(int, int)
     * @see org.signserver.mailsigner.cli.IMailSignerRMI#destroyKey(int, int)
     */
    public boolean destroyKey(int signerId, int purpose)
            throws InvalidWorkerIdException, RemoteException {
        return getWorkerSession().destroyKey(signerId, purpose);
    }

    public String generateKey(final int signerId,
            final String keyAlgorithm, final String keySpec,
            final String alias, final char[] authCode)
            throws CryptoTokenOfflineException,
            InvalidWorkerIdException, RemoteException {
        return getWorkerSession().generateSignerKey(signerId, keyAlgorithm,
                keySpec, alias, authCode);
    }

    public Collection<KeyTestResult> testKey(final int signerId,
            final String alias, final char[] authCode)
            throws CryptoTokenOfflineException, InvalidWorkerIdException,
            KeyStoreException, RemoteException {
        return getWorkerSession().testKey(signerId, alias, authCode);
    }

    /**
     * @see org.signserver.ejb.WorkerSessionBean#genCertificateRequest(int, ISignerCertReqInfo)
     */
    public ICertReqData genCertificateRequest(int signerId,
            ISignerCertReqInfo certReqInfo,
            final boolean explicitEccParameter,
            final boolean defaultKey)
            throws CryptoTokenOfflineException,
            InvalidWorkerIdException, RemoteException {
        return getWorkerSession().getCertificateRequest(
                signerId, certReqInfo, explicitEccParameter,
                defaultKey);
    }

    /**
     * @see org.signserver.ejb.WorkerSessionBean#getCurrentSignerConfig(int)
     * @see org.signserver.mailsigner.cli.IMailSignerRMI#getCurrentSignerConfig(int)
     */
    public WorkerConfig getCurrentWorkerConfig(int signerId)
            throws RemoteException {
        return getWorkerSession().getCurrentWorkerConfig(signerId);
    }

    /**
     * @see org.signserver.ejb.GlobalConfigurationSessionBean#getGlobalConfiguration()
     * @see org.signserver.mailsigner.cli.IMailSignerRMI#getGlobalConfiguration()
     */
    public GlobalConfiguration getGlobalConfiguration() throws RemoteException {
        return getGlobalConfigurationSession().getGlobalConfiguration();
    }

    /**
     * @see org.signserver.ejb.WorkerSessionBean#getWorkerId(String)
     * @see org.signserver.mailsigner.cli.IMailSignerRMI#getWorkerId(String)
     */
    public int getWorkerId(String signerName) throws RemoteException {
        return getWorkerSession().getWorkerId(signerName);
    }

    /**
     * @see org.signserver.ejb.WorkerSessionBean#getStatus(int)
     * @see org.signserver.mailsigner.cli.IMailSignerRMI#getStatus(int)
     */
    public WorkerStatus getStatus(int workerId)
            throws InvalidWorkerIdException, RemoteException {
        return getWorkerSession().getStatus(workerId);
    }

    /**
     * @see org.signserver.ejb.WorkerSessionBean#reloadConfiguration(int)
     * @see org.signserver.mailsigner.cli.IMailSignerRMI#reloadConfiguration(int)
     */
    public void reloadConfiguration(int workerId) throws RemoteException {
        getWorkerSession().reloadConfiguration(workerId);
    }

    /**
     * @see org.signserver.ejb.GlobalConfigurationSessionBean#removeProperty(String, String)
     * @see org.signserver.mailsigner.cli.IMailSignerRMI#removeGlobalProperty(String, String)
     */
    public boolean removeGlobalProperty(String scope, String key)
            throws RemoteException {
        return getGlobalConfigurationSession().removeProperty(scope, key);
    }

    /**
     * @see org.signserver.ejb.WorkerSessionBean#removeWorkerProperty(int, String)
     * @see org.signserver.mailsigner.cli.IMailSignerRMI#removeWorkerProperty(int, String)
     */
    public boolean removeWorkerProperty(int workerId, String key)
            throws RemoteException {
        return getWorkerSession().removeWorkerProperty(workerId, key);
    }

    /**
     * @see org.signserver.ejb.GlobalConfigurationSessionBean#setProperty(String, String, String)
     * @see org.signserver.mailsigner.cli.IMailSignerRMI#setGlobalProperty(String, String, String)
     */
    public void setGlobalProperty(String scope, String key, String value)
            throws RemoteException {
        getGlobalConfigurationSession().setProperty(scope, key, value);
    }

    public void setStatusProperty(final String key, final String value)
            throws RemoteException {
        getStatusRepositorySession().setProperty(key, value);
    }

    public void setStatusProperty(final String key, final String value,
            final long expiration) throws RemoteException {
        getStatusRepositorySession().setProperty(key, value,
                expiration);
    }

    public String getStatusProperty(final String key)
            throws RemoteException {
        return getStatusRepositorySession().getProperty(key);
    }

    public List<Integer> getWorkers(int workerType) throws RemoteException {
        return getGlobalConfigurationSession().getWorkers(workerType);
    }

    /**
     * @see org.signserver.ejb.WorkerSessionBean#setWorkerProperty(int, String, String)
     * @see org.signserver.mailsigner.cli.IMailSignerRMI#setWorkerProperty(int, String, String)	 
     */
    public void setWorkerProperty(int workerId, String key, String value)
            throws RemoteException {
        getWorkerSession().setWorkerProperty(workerId, key, value);
    }

    /**
     * @see org.signserver.ejb.WorkerSessionBean#uploadSignerCertificate(int, X509Certificate)
     * @see org.signserver.mailsigner.cli.IMailSignerRMI#uploadSignerCertificate(int, X509Certificate)	 
     */
    public void uploadSignerCertificate(int signerId, byte[] signerCert, String scope)
            throws RemoteException, CertificateException {
        getWorkerSession().uploadSignerCertificate(signerId, signerCert, scope);
    }

    /**
     * @see org.signserver.ejb.WorkerSessionBean#uploadSignerCertificateChain(int, Collection)
     * @see org.signserver.mailsigner.cli.IMailSignerRMI#uploadSignerCertificateChain(int, Collection)	 
     */
    public void uploadSignerCertificateChain(int signerId,
            Collection<byte[]> signerCerts, String scope)
            throws RemoteException, CertificateException {
        getWorkerSession().uploadSignerCertificateChain(signerId, signerCerts, scope);
    }

    /**
     * @see org.signserver.ejb.WorkerSessionBean#genFreeWorkerId()
     * @see org.signserver.mailsigner.cli.IMailSignerRMI#genFreeWorkerId()
     */
    public int genFreeWorkerId() throws RemoteException {
        return getWorkerSession().genFreeWorkerId();
    }

    public void resync() throws RemoteException, ResyncException {
        getGlobalConfigurationSession().resync();
    }

    /**
     * @see org.signserver.ejb.WorkerSessionBean#process(int, org.signserver.common.ProcessRequest, org.signserver.common.RequestContext)
     */
    public ProcessResponse processRequest(int workerId, ProcessRequest request) throws RemoteException, IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        return getWorkerSession().process(workerId, request, new RequestContext(true));
    }

    /**
     * Method only supported by SignServer Builds
     * @throws RemoteException 
     * 
     * @see org.signserver.ejb.WorkerSessionBean#getAuthorizedClients(int)
     */
    public Collection<AuthorizedClient> getAuthorizedClients(int signerId) throws RemoteException {
        return getWorkerSession().getAuthorizedClients(signerId);
    }

    /**
     * Method adding an authorized client to a signer
     * 
     * @param signerId
     * @param authClient
     * @throws RemoteException 
     * 
     */
    public void addAuthorizedClient(int signerId, AuthorizedClient authClient) throws RemoteException {
        getWorkerSession().addAuthorizedClient(signerId, authClient);
    }

    /**
     * Removes an authorized client from a signer
     * 
     * @param signerId
     * @param authClient
     * @throws RemoteException 
     * 
     */
    public boolean removeAuthorizedClient(int signerId, AuthorizedClient authClient) throws RemoteException {
        return getWorkerSession().removeAuthorizedClient(signerId, authClient);
    }

    public ArchiveDataVO findArchiveDataFromArchiveId(int signerid,
            String archiveid) throws RemoteException {
        return getWorkerSession().findArchiveDataFromArchiveId(signerid, archiveid);
    }

    public List<ArchiveDataVO> findArchiveDatasFromRequestCertificate(int signerid,
            BigInteger sn, String issuerdn) throws RemoteException {
        return getWorkerSession().findArchiveDatasFromRequestCertificate(signerid, sn, issuerdn);
    }

    public List<ArchiveDataVO> findArchiveDatasFromRequestIP(int signerid, String requestIP) throws RemoteException {
        return getWorkerSession().findArchiveDatasFromRequestIP(signerid, requestIP);
    }

    /**
     * Gets GlobalConfigurationSession Remote.
     * @return SignServerSession
     * @throws RemoteException in case the lookup failed
     */
    private IGlobalConfigurationSession.IRemote getGlobalConfigurationSession()
            throws RemoteException {
        if (globalConfig == null) {
            try {
                globalConfig = ServiceLocator.getInstance().lookupRemote(
                        IGlobalConfigurationSession.IRemote.class);
            } catch (NamingException e) {
                LOG.error("Error instanciating the GlobalConfigurationSession.", e);
                throw new RemoteException("Error instanciating the GlobalConfigurationSession", e);
            }
        }
        return globalConfig;
    }

    /**
     * Gets StatusRepositorySession Remote.
     * @return SignServerSession
     * @throws RemoteException in case the lookup failed
     */
    private IStatusRepositorySession.IRemote getStatusRepositorySession()
            throws RemoteException {
        if (statusRepository == null) {
            try {
                statusRepository = ServiceLocator.getInstance().lookupRemote(
                        IStatusRepositorySession.IRemote.class);
            } catch (NamingException e) {
                LOG.error("Error instanciating the StatusRepositorySession.", e);
                throw new RemoteException(
                        "Error instanciating the StatusRepositorySession", e);
            }
        }
        return statusRepository;
    }

    /**
     * Gets SignServerSession Remote.
     * @return SignServerSession
     * @throws RemoteException in case the lookup failed
     */
    private IWorkerSession.IRemote getWorkerSession() throws RemoteException {
        if (signsession == null) {
            try {
                signsession = ServiceLocator.getInstance().lookupRemote(
                        IWorkerSession.IRemote.class);
            } catch (NamingException e) {
                LOG.error("Error looking up signserver interface");
                throw new RemoteException("Error looking up signserver interface", e);
            }
        }
        return signsession;
    }

    public Map<String, StatusRepositoryData> getStatusProperties() throws RemoteException {
        return getStatusRepositorySession().getProperties();
    }
}
