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

import org.signserver.common.WorkerIdentifier;
import java.math.BigInteger;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.query.QueryCriteria;
import org.signserver.common.ArchiveDataVO;
import org.signserver.common.ArchiveMetadata;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.CertificateMatchingRule;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.KeyTestResult;
import org.signserver.common.OperationUnsupportedException;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.common.WorkerType;

/**
 * Interface for the worker session bean.
 *
 * @version $Id$
 */
public interface WorkerSession {

    /**
     * Returns the current status of a processalbe.
     *
     * Should be used with the cmd-line status command.
     * @param wi of the signer
     * @return a WorkerStatus class
     * @throws InvalidWorkerIdException in case the worker does not exist
     */
    WorkerStatus getStatus(WorkerIdentifier wi) throws InvalidWorkerIdException;

    /**
     * Returns if the associated crypto token is active or not.
     *
     * @param workerId of the worker to check
     * @return true if the crypto token is active
     * @throws InvalidWorkerIdException  in case the worker does not exist
     */
    boolean isTokenActive(WorkerIdentifier workerId) throws InvalidWorkerIdException;

    /**
     * Returns the Id of a worker given a name
     *
     * @param workerName of the worker, cannot be null
     * @return The Id of a named worker or 0 if no such name exists
     * @throws InvalidWorkerIdException in case the worker does not exist
     */
    int getWorkerId(String workerName) throws InvalidWorkerIdException;

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
     * @throws InvalidWorkerIdException in case the worker does not exist
     */
    void activateSigner(WorkerIdentifier signerId, String authenticationCode)
            throws CryptoTokenAuthenticationFailureException,
            CryptoTokenOfflineException, InvalidWorkerIdException;

    /**
     * Method used to deactivate the signtoken of a signer.
     * Should be called from the command line.
     *
     * @param signerId of the signer
     * @return true if deactivation was successful
     * @throws CryptoTokenOfflineException
     * @throws InvalidWorkerIdException in case the worker does not exist
     */
    boolean deactivateSigner(WorkerIdentifier signerId) throws CryptoTokenOfflineException,
            InvalidWorkerIdException;

    /**
     * Returns the current configuration of a worker. Only the worker properties
     * are included in the WorkerConfig instance returned.
     * Prior to version 3.7.0 the returned WorkerConfig instance also contained
     * authorized clients and the signer certificate and chain.
     * Use the dedicated methods to retrieve this data.
     *
     * Observe that this config might not be active until a reload command
     * has been excecuted.
     *
     * @param signerId
     * @return the current (not always active) configuration
     */
    WorkerConfig getCurrentWorkerConfig(int signerId);

    /**
     * Exports a worker's properties excluding sensitive ones
     * (as configured by deploy-time properties)
     * 
     * @param signerId
     * @return current worker properties, excluding sensitive
     */
    Properties exportWorkerConfig(int signerId);
    
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
     * Sets several parameters in a workers configuration, additions, deletions and edits.
     *
     * Observe that the worker isn't activated with this config until reload is
     * performed.
     *
     * @param workerId ID of worker to set (add/edit/delete) properties on
     * @param propertiesAndValues new/adjusted properties that are to be saved
     * @param propertiesToRemove properties to remove
     */
    void updateWorkerProperties(int workerId,
                                Map<String, String> propertiesAndValues,
                                List<String> propertiesToRemove);
    
    /**
     * Method that returns a collection of AuthorizedClient of
     * client certificate sn and issuerid accepted for a given signer.
     *
     * @param signerId
     * @return Sorted collection of authorized clients
     */
    Collection<AuthorizedClient> getAuthorizedClients(int signerId);
    
    /**
     * Method that returns a collection of AuthorizedClient of
     * client certificate sn and issuerid accepted for a given signer.
     *
     * @param signerId
     * @return Sorted collection of authorized clients
     */
    Collection<CertificateMatchingRule> getAuthorizedClientsGen2(int signerId);

    /**
     * Method adding an authorized client to a signer.

     * @param signerId
     * @param authClient
     */
    void addAuthorizedClient(int signerId, AuthorizedClient authClient);
    
    /**
     * Method adding an authorized client to a signer.

     * @param signerId
     * @param authClient
     */
    void addAuthorizedClientGen2(int signerId, CertificateMatchingRule authClient);

    /**
     * Removes an authorized client from a signer.
     *
     * @param signerId
     * @param authClient
     * @return true if the client was found and removed
     */
    boolean removeAuthorizedClient(int signerId, AuthorizedClient authClient);
    
    /**
     * Removes an authorized client from a signer.
     *
     * @param signerId
     * @param authClient
     * @return true if the client was found and removed
     */
    boolean removeAuthorizedClientGen2(int signerId, CertificateMatchingRule authClient);

    /**
     * Method used to let a signer generate a certificate request
     * using the signers own genCertificateRequest method.
     *
     * @param signerId id of the signer
     * @param certReqInfo information used by the signer to create the request
     * @param explicitEccParameters false should be default and will use
     * NamedCurve encoding of ECC public keys (IETF recommendation), use true
     * to include all parameters explicitly (ICAO ePassport requirement).
     * @return the CSR
     * @throws CryptoTokenOfflineException
     * @throws InvalidWorkerIdException in case the worker does not exist
     */
    ICertReqData getCertificateRequest(WorkerIdentifier signerId,
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
     * @return the CSR
     * @throws CryptoTokenOfflineException
     * @throws InvalidWorkerIdException in case the worker does not exist
     */
    ICertReqData getCertificateRequest(WorkerIdentifier signerId,
            ISignerCertReqInfo certReqInfo, boolean explicitEccParameters, 
            boolean defaultKey) throws CryptoTokenOfflineException,
            InvalidWorkerIdException;
    
    /**
     * Method used to let a signer generate a certificate request
     * using the signers own genCertificateRequest method given a key alias.
     * 
     * @param signerId ID of the signer
     * @param certReqInfo information used by the signer to create the request
     * @param explicitEccParameters false should be default and will use
     * NamedCurve encoding of ECC public keys (IETF recommendation), use true
     * to include all parameters explicitly (ICAO ePassport requirement).
     * @param keyAlias key alias to use in the crypto token.
     * @return Certificate request data
     * @throws CryptoTokenOfflineException
     * @throws InvalidWorkerIdException 
     */
    ICertReqData getCertificateRequest(WorkerIdentifier signerId,
            ISignerCertReqInfo certReqInfo, boolean explicitEccParameters,
            String keyAlias)
            throws CryptoTokenOfflineException, InvalidWorkerIdException;
            

    /**
     * Method returning the current signing certificate for the signer.
     * @param signerId Id of signer
     * @return Current signing certificate if the worker is a signer and it has
     * been configured. Otherwise null or an exception is thrown.
     * @throws CryptoTokenOfflineException In case the crypto token or the worker
     * is not active
     */
    Certificate getSignerCertificate(WorkerIdentifier signerId)
            throws CryptoTokenOfflineException;
    
    /**
     * Method returning the current signing certificate for the signer.
     * @param signerId Id of signer
     * @return Current signing certificate if the worker is a signer and it has
     * been configured. Otherwise null or an exception is thrown.
     * @throws CryptoTokenOfflineException In case the crypto token or the worker
     * is not active
     */
    byte[] getSignerCertificateBytes(WorkerIdentifier signerId)
            throws CryptoTokenOfflineException;

    /**
     * Method returning the current signing certificate chain for the signer.
     * @param signerId Id of signer
     * @return Current signing certificate chain if the worker is a signer and it
     * has been configured. Otherwise null or an exception is thrown.
     * @throws CryptoTokenOfflineException In case the crypto token or the worker
     * is not active
     */
    public List<Certificate> getSignerCertificateChain(WorkerIdentifier signerId)
            throws CryptoTokenOfflineException;
    
    /**
     * Method returning the signing certificate chain for the signer given
     * a key alias.
     * 
     * @param signerId
     * @param alias
     * @return The certificate chain, or null if there is no chain for the
     *         given alias
     * @throws CryptoTokenOfflineException 
     * @throws InvalidWorkerIdException
     */
    public List<Certificate> getSignerCertificateChain(WorkerIdentifier signerId,
                                                       String alias)
            throws CryptoTokenOfflineException, InvalidWorkerIdException;
    
    /**
     * Method returning the current signing certificate chain for the signer.
     * @param signerId Id of signer
     * @return Current signing certificate chain if the worker is a signer and it
     * has been configured. Otherwise null or an exception is thrown.
     * @throws CryptoTokenOfflineException In case the crypto token or the worker
     * is not active
     */
    public List<byte[]> getSignerCertificateChainBytes(WorkerIdentifier signerId)
            throws CryptoTokenOfflineException;

    /**
     * Gets the last date the specified worker can do signings.
     * @param workerId Id of worker to check.
     * @return The last date or null if no last date (=unlimited).
     * @throws CryptoTokenOfflineException In case the cryptotoken is offline
     * for some reason.
     */
    Date getSigningValidityNotAfter(WorkerIdentifier workerId)
            throws CryptoTokenOfflineException;

    /**
     * Gets the first date the specified worker can do signings.
     * @param workerId Id of worker to check.
     * @return The first date or null if no last date (=unlimited).
     * @throws CryptoTokenOfflineException In case the cryptotoken is offline
     * for some reason.
     */
    Date getSigningValidityNotBefore(WorkerIdentifier workerId)
            throws CryptoTokenOfflineException;

    /**
     * Returns the value of the KeyUsageCounter for the given workerId. If no
     * certificate is configured for the worker or the current key does not yet
     * have a counter in the database -1 is returned.
     * @param workerId
     * @return Value of the key usage counter or -1
     * @throws CryptoTokenOfflineException
     */
    long getKeyUsageCounterValue(final WorkerIdentifier workerId) 
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
    boolean removeKey(WorkerIdentifier signerId, String alias) 
            throws CryptoTokenOfflineException, InvalidWorkerIdException, 
            KeyStoreException, SignServerException;
    
    /**
     * Generate a new keypair.
     * @param signerId Id of signer
     * @param keyAlgorithm Key algorithm
     * @param keySpec Key specification
     * @param alias Name of the new key
     * @param authCode Authorization code
     * @return key alias of the generated key
     * @throws CryptoTokenOfflineException
     * @throws IllegalArgumentException
     * @throws InvalidWorkerIdException in case the worker does not exist
     */
    String generateSignerKey(WorkerIdentifier signerId, String keyAlgorithm,
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
     * @throws InvalidWorkerIdException in case the worker does not exist
     */
    Collection<KeyTestResult> testKey(final WorkerIdentifier signerId, final String alias,
            char[] authCode) throws CryptoTokenOfflineException,
            InvalidWorkerIdException, KeyStoreException;
    
    /**
     * Method used to upload a certificate to a signers active configuration.
     *
     * @param signerId id of the signer
     * @param signerCert the certificate used to sign signature requests
     * @param scope one of GlobalConfiguration.SCOPE_ constants
     * @throws CertificateException
     */
    void uploadSignerCertificate(int signerId, byte[] signerCert,
            String scope) throws CertificateException;

    /**
     * Method used to upload a complete certificate chain to a configuration
     *
     * @param signerId id of the signer
     * @param signerCerts the certificate chain used to sign signature requests
     * @param scope one of GlobalConfiguration.SCOPE_ constants
     * @throws CertificateException
     */
    void uploadSignerCertificateChain(int signerId, List<byte[]> signerCerts, String scope)
             throws CertificateException;

    /**
     * Method used to import a complete certificate chain to a crypto token.
     * 
     * @param signerId ID of the signer
     * @param signerCerts the certificate chain to upload
     * @param alias key alias to use in the token
     * @param authenticationCode authentication code used for the key entry,
     *                          or use the authentication code used when activating
     *                          the token if null
     * @throws CryptoTokenOfflineException
     * @throws CertificateException
     * @throws OperationUnsupportedException 
     */
    void importCertificateChain(WorkerIdentifier signerId, List<byte[]> signerCerts,
                                String alias,char[] authenticationCode)
            throws CryptoTokenOfflineException, CertificateException,
                   OperationUnsupportedException;
    
    /**
     * Methods that generates a free worker id that can be used for new signers.
     * @return the worker ID
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
     * Query contents of archive.
     * Returns meta data entries of archive entries matching query criteria.
     * 
     * @param startIndex Start index of first result (0-based)
     * @param max Maximum number of results returned, 0 means all matching results
     * @param criteria Search criteria for matching results
     * @param includeData If true, include actual archive data in entries
     * @return List of metadata objects describing matching entries
     * @throws AuthorizationDeniedException
     */
    List<ArchiveMetadata> searchArchive(int startIndex,
            int max, QueryCriteria criteria, boolean includeData)
            throws AuthorizationDeniedException; 
    
    /**
     * Query contents of archive based on list of uniqueIds (primary key in DB).
     * 
     * @param uniqueIds List of IDs to fetch meta data for
     * @param includeData If true, include actual archive data in entries
     * @return List of archive data objects
     * @throws AuthorizationDeniedException
     */
    List<ArchiveMetadata> searchArchiveWithIds(List<String> uniqueIds,
            boolean includeData)
            throws AuthorizationDeniedException;
    
    /**
     * Get all workers of the give type.
     * @param workerType to obtain the IDs for
     * @return list of worker IDs
     */
    List<Integer> getWorkers(WorkerType workerType);

    /**
     * Get the complete list of workers of any type.
     * @return list of worker IDs 
     */
    List<Integer> getAllWorkers();
    
    /**
     * Get the complete list of all worker names.
     *
     * @return list of worker names
     */
    List<String> getAllWorkerNames();

    /**
     * Checks if there are any issues using this certificate chain with the specfied worker.
     *
     * @param workerId worker to ask about the certificate chain
     * @param certificateChain to check
     * @return each certificate issue found
     * @throws InvalidWorkerIdException in case a worker with the specified ID is not available
     */
    List<String> getCertificateIssues(int workerId, List<Certificate> certificateChain) throws InvalidWorkerIdException;
}
