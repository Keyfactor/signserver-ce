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
package org.signserver.ejb.interfaces;

import java.math.BigInteger;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import javax.ejb.Local;
import javax.ejb.Remote;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.query.QueryCriteria;
import org.signserver.common.ArchiveDataVO;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.KeyTestResult;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.server.log.AdminInfo;

/**
 * Interface for the worker session bean.
 *
 * @version $Id$
 */
public interface IWorkerSession {

    /**
     * The Worker Beans main method. Takes  requests processes them
     * and returns a response.
     *
     * @param workerId id of worker who should process the request
     * @param request the request
     * @param requestContext context of the request
     * @throws CryptoTokenOfflineException if the signers token isn't activated.
     * @throws IllegalRequestException if illegal request is sent to the method
     * @throws SignServerException if some other error occurred server side
     * during process.
     */
    ProcessResponse process(int workerId, ProcessRequest request,
            RequestContext requestContext)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException;

    /**
     * Returns the current status of a processalbe.
     *
     * Should be used with the cmd-line status command.
     * @param workerId of the signer
     * @return a WorkerStatus class
     */
    WorkerStatus getStatus(int workerId) throws InvalidWorkerIdException;

    /**
     * Returns the Id of a worker given a name
     *
     * @param workerName of the worker, cannot be null
     * @return The Id of a named worker or 0 if no such name exists
     */
    int getWorkerId(String workerName);

    /**
     * Method used when a configuration have been updated. And should be
     * called from the commandline.
     *
     * @param workerId of the worker that should be reloaded, or 0 to reload
     * reload of all available workers
     */
    void reloadConfiguration(int workerId);

    /**
     * Method used to activate the signtoken of a signer.
     * Should be called from the command line.
     *
     * @param signerId of the signer
     * @param authenticationCode (PIN) used to activate the token.
     * @throws CryptoTokenOfflineException
     * @throws CryptoTokenAuthenticationFailureException
     */
    void activateSigner(int signerId, String authenticationCode)
            throws CryptoTokenAuthenticationFailureException,
            CryptoTokenOfflineException, InvalidWorkerIdException;

    /**
     * Method used to deactivate the signtoken of a signer.
     * Should be called from the command line.
     *
     * @param signerId of the signer
     * @return true if deactivation was successful
     * @throws CryptoTokenOfflineException
     * @throws CryptoTokenAuthenticationFailureException
     */
    boolean deactivateSigner(int signerId) throws CryptoTokenOfflineException,
            InvalidWorkerIdException;

    /**
     * Returns the current configuration of a worker.
     *
     * Observe that this config might not be active until a reload command
     * has been excecuted.
     *
     * @param signerId
     * @return the current (not always active) configuration
     */
    WorkerConfig getCurrentWorkerConfig(int signerId);

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
    void setWorkerProperty(int workerId, String key, String value);

    /**
     * Removes a given worker's property.
     *
     * @param workerId
     * @param key
     * @return true if the property did exist and was removed othervise false
     */
    boolean removeWorkerProperty(int workerId, String key);

    /**
     * Method that returns a collection of AuthorizedClient of
     * client certificate sn and issuerid accepted for a given signer.
     *
     * @param signerId
     * @return Sorted collection of authorized clients
     */
    Collection<AuthorizedClient> getAuthorizedClients(int signerId);

    /**
     * Method adding an authorized client to a signer.

     * @param signerId
     * @param authClient
     */
    void addAuthorizedClient(int signerId, AuthorizedClient authClient);

    /**
     * Removes an authorized client from a signer.
     *
     * @param signerId
     * @param authClient
     */
    boolean removeAuthorizedClient(int signerId, AuthorizedClient authClient);

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
    ICertReqData getCertificateRequest(int signerId,
            ISignerCertReqInfo certReqInfo, boolean explicitEccParameters)
            throws CryptoTokenOfflineException, InvalidWorkerIdException;

    /**
     * Method used to let a signer generate a certificate request
     * using the signers own genCertificateRequest method.
     *
     * @param signerId id of the signer
     * @param certReqInfo information used by the signer to create the request
     * @param explicitEccParameters false should be default and will use
     * NamedCurve encoding of ECC public keys (IETF recommendation), use true
     * to include all parameters explicitly (ICAO ePassport requirement).
     * @param defaultKey true if the default key should be used otherwise for
     * instance use next key.
     */
    ICertReqData getCertificateRequest(int signerId,
            ISignerCertReqInfo certReqInfo, boolean explicitEccParameters, 
            boolean defaultKey) throws CryptoTokenOfflineException,
            InvalidWorkerIdException;

    /**
     * Method returning the current signing certificate for the signer.
     * @param signerId Id of signer
     * @return Current signing certificate if the worker is a signer and it has
     * been configured. Otherwise null or an exception is thrown.
     * @throws CryptoTokenOfflineException In case the crypto token or the worker
     * is not active
     */
    Certificate getSignerCertificate(int signerId)
            throws CryptoTokenOfflineException;
    
    /**
     * Method returning the current signing certificate for the signer.
     * @param signerId Id of signer
     * @return Current signing certificate if the worker is a signer and it has
     * been configured. Otherwise null or an exception is thrown.
     * @throws CryptoTokenOfflineException In case the crypto token or the worker
     * is not active
     */
    byte[] getSignerCertificateBytes(int signerId)
            throws CryptoTokenOfflineException;

    /**
     * Method returning the current signing certificate chain for the signer.
     * @param signerId Id of signer
     * @return Current signing certificate chain if the worker is a signer and it
     * has been configured. Otherwise null or an exception is thrown.
     * @throws CryptoTokenOfflineException In case the crypto token or the worker
     * is not active
     */
    public List<Certificate> getSignerCertificateChain(int signerId)
            throws CryptoTokenOfflineException;
    
    /**
     * Method returning the current signing certificate chain for the signer.
     * @param signerId Id of signer
     * @return Current signing certificate chain if the worker is a signer and it
     * has been configured. Otherwise null or an exception is thrown.
     * @throws CryptoTokenOfflineException In case the crypto token or the worker
     * is not active
     */
    public List<byte[]> getSignerCertificateChainBytes(int signerId)
            throws CryptoTokenOfflineException;

    /**
     * Gets the last date the specified worker can do signings.
     * @param workerId Id of worker to check.
     * @return The last date or null if no last date (=unlimited).
     * @throws CryptoTokenOfflineException In case the cryptotoken is offline
     * for some reason.
     */
    Date getSigningValidityNotAfter(int workerId)
            throws CryptoTokenOfflineException;

    /**
     * Gets the first date the specified worker can do signings.
     * @param workerId Id of worker to check.
     * @return The first date or null if no last date (=unlimited).
     * @throws CryptoTokenOfflineException In case the cryptotoken is offline
     * for some reason.
     */
    Date getSigningValidityNotBefore(int workerId)
            throws CryptoTokenOfflineException;

    /**
     * Returns the value of the KeyUsageCounter for the given workerId. If no
     * certificate is configured for the worker or the current key does not yet
     * have a counter in the database -1 is returned.
     * @param workerId
     * @return Value of the key usage counter or -1
     * @throws CryptoTokenOfflineException
     */
    long getKeyUsageCounterValue(final int workerId) 
            throws CryptoTokenOfflineException;

    /**
     * Attempt to remove the specified key with the key alias.
     *
     * @param signerId of worker
     * @param alias of key to remove
     * @return true if the key was removed or false if the removal failed or 
     * the worker or crypto token does not support key removal
     * @throws CryptoTokenOfflineException in case the token was not activated
     * @throws InvalidWorkerIdException in case the worker could not be fined
     * @throws KeyStoreException for keystore related errors
     * @throws SignServerException in case the key alias could not be found etc
     */
    boolean removeKey(int signerId, String alias) 
            throws CryptoTokenOfflineException, InvalidWorkerIdException, 
            KeyStoreException, SignServerException;
    
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
    String generateSignerKey(int signerId, String keyAlgorithm,
            String keySpec, String alias, char[] authCode)
            throws CryptoTokenOfflineException, InvalidWorkerIdException;

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
    Collection<KeyTestResult> testKey(final int signerId, final String alias,
            char[] authCode) throws CryptoTokenOfflineException,
            InvalidWorkerIdException, KeyStoreException;
    
    /**
     * Method used to upload a certificate to a signers active configuration.
     *
     * @param signerId id of the signer
     * @param signerCert the certificate used to sign signature requests
     * @param scope one of GlobalConfiguration.SCOPE_ constants
     */
    void uploadSignerCertificate(int signerId, byte[] signerCert,
            String scope) throws CertificateException;

    /**
     * Method used to upload a complete certificate chain to a configuration
     *
     * @param signerId id of the signer
     * @param signerCerts the certificate chain used to sign signature requests
     * @param scope one of GlobalConfiguration.SCOPE_ constants
     */
    void uploadSignerCertificateChain(int signerId,
            Collection<byte[]> signerCerts, String scope)
             throws CertificateException;

    /**
     * Methods that generates a free worker id that can be used for new signers.
     */
    int genFreeWorkerId();

    /**
     * Find all archivables related to an ArchiveId from the given signer. Both REQUEST, RESPONSE and 
     * possibly other Archivable types are returned.
     * @param signerId id of the signer
     * @param archiveId the Id of te archive data
     * @return List of all ArchiveDataVO related to one archiveId
     */
    List<ArchiveDataVO> findArchiveDataFromArchiveId(int signerId, String archiveId);
    
    /**
     * Find all archivables related to an requestIP from the given signer. Both REQUEST, RESPONSE and 
     * possibly other Archivable types are returned.
     * @param signerId id of the signer
     * @param requestIP the IP of the client
     * @return List of all ArchiveDataVO
     */
    List<ArchiveDataVO> findArchiveDatasFromRequestIP(int signerId,
            String requestIP);
    
    /** 
     * Find all archivables related to an request certificate from the given signer. Both REQUEST, RESPONSE and 
     * possibly other Archivable types are returned.
     * @param signerId id of the signer
     * @param serialNumber the serialnumber of the certificate
     * making the request
     * @param issuerDN the issuer of the client certificate
     * @return List of all ArchiveDataVO
     */
    List<ArchiveDataVO> findArchiveDatasFromRequestCertificate(int signerId,
            BigInteger serialNumber, String issuerDN);
    
    /**
     * Help method that returns all worker, either signers or services defined
     * in the global configuration.
     * @param workerType can either be GlobalConfiguration.WORKERTYPE_ALL,
     * _SIGNERS or _SERVICES
     * @return A List if Integers of worker Ids, never null.
     */
    List<Integer> getWorkers(int workerType);

    @Remote
    interface IRemote extends IWorkerSession {

        String JNDI_NAME = "signserver/WorkerSessionBean/remote";
        
        List<? extends AuditLogEntry> selectAuditLogs(int startIndex, int max, QueryCriteria criteria, String logDeviceId) throws AuthorizationDeniedException;
    }

    /**
     * Local EJB interface.
     * This interface has mirror methods for all methods of the parent interface
     * related to audit logging, taking an additional AdminInfo instance.
     */
    @Local
    interface ILocal extends IWorkerSession { 
        String JNDI_NAME = "signserver/WorkerSessionBean/local";
        
        /**
         * Select a set of events to be audited.
         * 
         * @param token identifier of the entity performing the task.
         * @param startIndex Index where select will start. Set to 0 to start from the beginning.
         * @param max maximum number of results to be returned. Set to 0 to use no limit.
         * @param criteria Criteria defining the subset of logs to be selected.
         * @param logDeviceId identifier of the AuditLogDevice
         * 
         * @return The audit logs to the given criteria
         * @throws AuthorizationDeniedException 
         */
        List<? extends AuditLogEntry> selectAuditLogs(AdminInfo adminInfo, int startIndex, int max, QueryCriteria criteria, String logDeviceId) throws AuthorizationDeniedException;
    
        /**
         * Method used to remove a key from a signer.
         *
         * @param adminInfo administrator info
         * @param signerId id of the signer
         * @param purpose on of ICryptoToken.PURPOSE_ constants
         * @return true if removal was successful.
         */
//        boolean destroyKey(final AdminInfo adminInfo, int signerId, int purpose)
//                throws InvalidWorkerIdException;
    
        boolean removeKey(AdminInfo adminInfo, int signerId, String alias) 
            throws CryptoTokenOfflineException, InvalidWorkerIdException, 
            KeyStoreException, SignServerException;
        
        /**
         * Generate a new keypair.
         * 
         * @param adminInfo Administrator info
         * @param signerId Id of signer
         * @param keyAlgorithm Key algorithm
         * @param keySpec Key specification
         * @param alias Name of the new key
         * @param authCode Authorization code
         * @throws CryptoTokenOfflineException
         * @throws IllegalArgumentException
         */
        String generateSignerKey(final AdminInfo adminInfo, int signerId, String keyAlgorithm,
                String keySpec, String alias, char[] authCode)
                        throws CryptoTokenOfflineException, InvalidWorkerIdException;
        
        /**
         * Tests the key identified by alias or all keys if "all" specified.
         *
         * @param adminInfo Administrator info
         * @param signerId Id of signer
         * @param alias Name of key to test or "all" to test all available
         * @param authCode Authorization code
         * @return Collection with test results for each key
         * @throws CryptoTokenOfflineException
         * @throws KeyStoreException
         */
        Collection<KeyTestResult> testKey(final AdminInfo adminInfo, final int signerId, String alias,
                char[] authCode)
                        throws CryptoTokenOfflineException, InvalidWorkerIdException,
                        KeyStoreException;
    
        /**
         * Sets a parameter in a workers configuration.
         *
         * Observe that the worker isn't activated with this config until reload
         * is performed.
         *
         * @param adminInfo
         * @param workerId
         * @param key
         * @param value
         */
        void setWorkerProperty(final AdminInfo adminInfo, int workerId, String key, String value);
        
        /**
         * Removes a given worker's property.
         *
         * @param adminInfo
         * @param workerId
         * @param key
         * @return true if the property did exist and was removed othervise false
         */
        boolean removeWorkerProperty(final AdminInfo adminInfo, int workerId, String key);
            
        /**
         * Method adding an authorized client to a signer.
         * 
         * @param adminInfo
         * @param signerId
         * @param authClient
         */
        void addAuthorizedClient(final AdminInfo adminInfo, int signerId, AuthorizedClient authClient);
            
        /**
         * Method removing an authorized client to a signer.
         * 
         * @param adminInfo
         * @param signerId
         * @param authClient
         * @return true if the client was authorized to the signer
         */
        boolean removeAuthorizedClient(final AdminInfo adminInfo, int signerId,
                    AuthorizedClient authClient);
            
        /**
         * Method used to let a signer generate a certificate request
         * using the signers own genCertificateRequest method.
         *
         * @param adminInfo Administrator info
         * @param signerId id of the signer
         * @param certReqInfo information used by the signer to create the request
         * @param explicitEccParameters false should be default and will use
         * NamedCurve encoding of ECC public keys (IETF recommendation), use true
         * to include all parameters explicitly (ICAO ePassport requirement).
         */
        ICertReqData getCertificateRequest(final AdminInfo adminInfo, int signerId,
                ISignerCertReqInfo certReqInfo,
                final boolean explicitEccParameters,
                final boolean defaultKey) throws
                CryptoTokenOfflineException, InvalidWorkerIdException;
            
        /**
         * Method used to let a signer generate a certificate request
         * using the signers own genCertificateRequest method.
         *
         * @param adminInfo Administrator info
         * @param signerId id of the signer
         * @param certReqInfo information used by the signer to create the request
         * @param explicitEccParameters false should be default and will use
         * NamedCurve encoding of ECC public keys (IETF recommendation), use true
         * to include all parameters explicitly (ICAO ePassport requirement).
         * @param defaultKey true if the default key should be used otherwise for
         * instance use next key.
         */
        ICertReqData getCertificateRequest(final AdminInfo adminInfo, final int signerId,
                final ISignerCertReqInfo certReqInfo,
                final boolean explicitEccParameters) throws
                CryptoTokenOfflineException, InvalidWorkerIdException;
            
        /**
         * Method used to upload a certificate to a signers active configuration.
         *
         * @param adminInfo Administrator info
         * @param signerId id of the signer
         * @param signerCert the certificate used to sign signature requests
         * @param scope one of GlobalConfiguration.SCOPE_ constants
         */
        void uploadSignerCertificate(final AdminInfo adminInfo, int signerId, byte[] signerCert,
                String scope) throws CertificateException;
            
        /**
         * Method used to upload a complete certificate chain to a configuration
         *
         * @param adminInfo Administrator info
         * @param signerId id of the signer
         * @param signerCerts the certificate chain used to sign signature requests
         * @param scope one of GlobalConfiguration.SCOPE_ constants
         */
        void uploadSignerCertificateChain(final AdminInfo adminInfo, int signerId,
                Collection<byte[]> signerCerts, String scope) throws CertificateException;

        
        /**
         * The Worker Beans main method. Takes  requests processes them
         * and returns a response.
         *
         * @param adminInfo Administrator information
         * @param workerId id of worker who should process the request
         * @param request the request
         * @param requestContext context of the request
         * @throws CryptoTokenOfflineException if the signers token isn't activated.
         * @throws IllegalRequestException if illegal request is sent to the method
         * @throws SignServerException if some other error occurred server side
         * during process.
         */
        ProcessResponse process(final AdminInfo info, int workerId, ProcessRequest request,
                RequestContext requestContext)
                throws IllegalRequestException, CryptoTokenOfflineException,
                SignServerException;
        
        /**
         * Method used when a configuration have been updated. And should be
         * called from the commandline.
         *
         * @param adminInfo Administrator information
         * @param workerId of the worker that should be reloaded, or 0 to reload
         * reload of all available workers
         */
        void reloadConfiguration(final AdminInfo adminInfo, int workerId);

    }
}
