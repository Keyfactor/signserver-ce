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
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import javax.ejb.Local;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.query.QueryCriteria;
import org.signserver.common.ArchiveMetadata;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.CertificateMatchingRule;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.KeyTestResult;
import org.signserver.common.OperationUnsupportedException;
import org.signserver.common.QueryException;
import org.signserver.common.SignServerException;
import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.server.cryptotokens.TokenSearchResults;
import org.signserver.server.log.AdminInfo;

/**
 * Local EJB interface. This interface has mirror methods for all methods of the
 * parent interface related to audit logging, taking an additional AdminInfo
 * instance.
 *
 * @version $Id$
 */
@Local
public interface WorkerSessionLocal extends WorkerSession {


    /**
     * Select a set of events to be audited.
     *
     * @param adminInfo administrator info
     * @param startIndex Index where select will start. Set to 0 to start from
     * the beginning.
     * @param max maximum number of results to be returned. Set to 0 to use no
     * limit.
     * @param criteria Criteria defining the subset of logs to be selected.
     * @param logDeviceId identifier of the AuditLogDevice
     *
     * @return The audit logs to the given criteria
     * @throws AuthorizationDeniedException
     */
    List<? extends AuditLogEntry> selectAuditLogs(AdminInfo adminInfo, int startIndex, int max, QueryCriteria criteria, String logDeviceId) throws AuthorizationDeniedException;

    /**
     * Method used to remove a key from a crypto token used by a worker.
     *
     * @param adminInfo administrator info
     * @param signerId id of the worker
     * @param alias key alias of key to remove
     * @return true if removal was successful.
     * @throws CryptoTokenOfflineException if crypto token was not activated or
     * could not be
     * @throws InvalidWorkerIdException if the specified worker id does not
     * exist
     * @throws KeyStoreException for keystore related errors
     * @throws SignServerException for other errors
     */
    boolean removeKey(AdminInfo adminInfo, WorkerIdentifier signerId, String alias)
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
     * @return key alias of the new key
     * @throws CryptoTokenOfflineException
     * @throws InvalidWorkerIdException
     * @throws IllegalArgumentException
     */
    String generateSignerKey(final AdminInfo adminInfo, WorkerIdentifier signerId, String keyAlgorithm,
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
     * @throws InvalidWorkerIdException
     * @throws KeyStoreException
     */
    Collection<KeyTestResult> testKey(final AdminInfo adminInfo, final WorkerIdentifier signerId, String alias,
            char[] authCode)
            throws CryptoTokenOfflineException, InvalidWorkerIdException,
            KeyStoreException;

    /**
     * Sets a parameter in a workers configuration.
     *
     * Observe that the worker isn't activated with this config until reload is
     * performed.
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
     * Sets several parameters in a workers configuration, additions, deletions and edits.
     *
     * Observe that the worker isn't activated with this config until reload is
     * performed.
     *
     * @param adminInfo
     * @param workerId ID of worker to set (add/edit/delete) properties on
     * @param propertiesAndValues new/adjusted properties that are to be saved
     * @param propertiesToRemove properties to remove
     */
    void updateWorkerProperties(AdminInfo adminInfo, int workerId,
                                Map<String, String> propertiesAndValues,
                                List<String> propertiesToRemove);
    
    /**
     * Method adding an authorized client to a signer.
     *
     * @param adminInfo
     * @param signerId
     * @param authClient
     */
    void addAuthorizedClient(final AdminInfo adminInfo, int signerId, AuthorizedClient authClient);
    
    /**
     * Method adding an authorized client to a signer.
     *
     * @param adminInfo
     * @param signerId
     * @param authClient
     */
    void addAuthorizedClientGen2(final AdminInfo adminInfo, int signerId, CertificateMatchingRule authClient);

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
     * Method removing an authorized client to a signer.
     *
     * @param adminInfo
     * @param signerId
     * @param authClient
     * @return true if the client was authorized to the signer
     */
    boolean removeAuthorizedClientGen2(final AdminInfo adminInfo, int signerId,
            CertificateMatchingRule authClient);

    /**
     * Method used to let a signer generate a certificate request using the
     * signers own genCertificateRequest method.
     *
     * @param adminInfo Administrator info
     * @param signerId id of the signer
     * @param certReqInfo information used by the signer to create the request
     * @param explicitEccParameters false should be default and will use
     * NamedCurve encoding of ECC public keys (IETF recommendation), use true to
     * include all parameters explicitly (ICAO ePassport requirement).
     * @param defaultKey
     * @return the CSR
     * @throws CryptoTokenOfflineException
     * @throws InvalidWorkerIdException
     */
    ICertReqData getCertificateRequest(final AdminInfo adminInfo, WorkerIdentifier signerId,
            ISignerCertReqInfo certReqInfo,
            final boolean explicitEccParameters,
            final boolean defaultKey) throws
            CryptoTokenOfflineException, InvalidWorkerIdException;

    /**
     * Method that gets the signing certificate chain given a key alias.
     *
     * @param adminInfo
     * @param signerId
     * @param alias
     * @return Certificate chain, or null if no such alias exists in the token
     * @throws CryptoTokenOfflineException
     * @throws InvalidWorkerIdException
     */
    List<Certificate> getSigningCertificateChain(AdminInfo adminInfo,
            WorkerIdentifier signerId,
            String alias)
            throws CryptoTokenOfflineException, InvalidWorkerIdException;

    /**
     * Method used to let a signer generate a certificate request using the
     * signers own genCertificateRequest method.
     *
     * @param adminInfo Administrator info
     * @param signerId id of the signer
     * @param certReqInfo information used by the signer to create the request
     * @param explicitEccParameters false should be default and will use
     * NamedCurve encoding of ECC public keys (IETF recommendation), use true to
     * include all parameters explicitly (ICAO ePassport requirement).
     * @return the CSR
     * @throws org.signserver.common.CryptoTokenOfflineException
     * @throws org.signserver.common.InvalidWorkerIdException
     */
    ICertReqData getCertificateRequest(final AdminInfo adminInfo, final WorkerIdentifier signerId,
            final ISignerCertReqInfo certReqInfo,
            final boolean explicitEccParameters) throws
            CryptoTokenOfflineException, InvalidWorkerIdException;

    /**
     * Method used to let a signer generate a certificate request using the
     * signers own genCertificateRequest method. Using the specified key alias
     * from the crypto token.
     *
     * @param adminInfo Administrator info
     * @param signerId id of the signer
     * @param certReqInfo information used by the signer to create the request
     * @param explicitEccParameters false should be default and will use
     * NamedCurve encoding of ECC public keys (IETF recommendation), use true to
     * include all parameters explicitly (ICAO ePassport requirement).
     * @param keyAlias key alias to use from the crypto token
     * @return certificate request data
     * @throws CryptoTokenOfflineException
     * @throws InvalidWorkerIdException
     */
    ICertReqData getCertificateRequest(final AdminInfo adminInfo, final WorkerIdentifier signerId,
            final ISignerCertReqInfo certReqInfo,
            final boolean explicitEccParameters, final String keyAlias)
            throws CryptoTokenOfflineException, InvalidWorkerIdException;

    /**
     * Get keystore data, used by the KeystoreInConfigCryptoToken.
     *
     * @param adminInfo Administrator info
     * @param signerId ID of the signer
     * @return Keystore data
     */
    byte[] getKeystoreData(final AdminInfo adminInfo, final int signerId);

    /**
     * Set keystore data, used by the KeystoreInConfigCryptoToken
     *
     * @param adminInfo Administator info
     * @param signerId ID of the signer
     * @param keystoreData Keystore data to set
     */
    void setKeystoreData(final AdminInfo adminInfo, final int signerId,
            final byte[] keystoreData);

    /**
     * Method used to upload a certificate to a signers active configuration.
     *
     * @param adminInfo Administrator info
     * @param signerId id of the signer
     * @param signerCert the certificate used to sign signature requests
     * @param scope one of GlobalConfiguration.SCOPE_ constants
     * @throws CertificateException
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
     * @throws CertificateException
     */
    void uploadSignerCertificateChain(final AdminInfo adminInfo, int signerId, List<byte[]> signerCerts, String scope) throws CertificateException;

    /**
     * Method used to import a complete certificate chain to a crypto token.
     *
     * @param adminInfo
     * @param signerId ID of the signer
     * @param signerCerts the certificate chain to upload
     * @param alias key alias to use in the token
     * @param authenticationCode authentication code for the key entry, or null
     * to use the token authentication code
     * @throws CryptoTokenOfflineException
     * @throws CertificateException
     * @throws OperationUnsupportedException
     */
    void importCertificateChain(AdminInfo adminInfo, WorkerIdentifier signerId,
            List<byte[]> signerCerts, String alias, char[] authenticationCode)
            throws CryptoTokenOfflineException, CertificateException,
            OperationUnsupportedException;

    /**
     * Method used when a configuration have been updated. And should be called
     * from the commandline.
     *
     * @param adminInfo Administrator information
     * @param workerId of the worker that should be reloaded, or 0 to reload
     * reload of all available workers
     */
    void reloadConfiguration(final AdminInfo adminInfo, int workerId);

    /**
     * Query contents of archive. Returns meta data entries of archive entries
     * matching query criteria.
     *
     * @param adminInfo Administrator information
     * @param startIndex Start index of first result (0-based)
     * @param max Maximum number of results returned, 0 means all matching
     * results
     * @param criteria Search criteria for matching results
     * @param includeData If true, archive data is included in the meta data
     * entries
     * @return List of metadata objects describing matching entries
     * @throws AuthorizationDeniedException
     */
    List<ArchiveMetadata> searchArchive(AdminInfo adminInfo,
            int startIndex, int max, QueryCriteria criteria,
            boolean includeData)
            throws AuthorizationDeniedException;

    /**
     * Query contents of archive based on list of unique IDs (primary key in
     * DB).
     *
     * @param adminInfo Administrator information
     * @param uniqueIds List of unique IDs to fetch entries for
     * @param includeData If true, archive data is included in the meta data
     * entries
     * @return List of archive data objects
     * @throws AuthorizationDeniedException
     */
    List<ArchiveMetadata> searchArchiveWithIds(final AdminInfo adminInfo,
            final List<String> uniqueIds,
            final boolean includeData)
            throws AuthorizationDeniedException;

    /**
     * Queries the specified worker's crypto token.
     *
     * @param adminInfo Administrator information
     * @param workerId Id of worker to query
     * @param startIndex Start index of first result (0-based)
     * @param max Maximum number of results to return
     * @param qc Search criteria for matching results
     * @param includeData If 'false' only the alias and key type is included,
     * otherwise all information available is returned
     * @param params Additional crypto token parameters to pass to the token
     * @return the search result
     * @throws OperationUnsupportedException in case the search operation is not
     * supported by the worker
     * @throws CryptoTokenOfflineException in case the token is not in a
     * searchable state
     * @throws QueryException in case the query could not be understood or could
     * not be executed
     * @throws InvalidWorkerIdException in case the worker ID is not existing
     * @throws InvalidAlgorithmParameterException
     * @throws UnsupportedCryptoTokenParameter
     * @throws AuthorizationDeniedException in case the operation was not
     * allowed
     */
    TokenSearchResults searchTokenEntries(final AdminInfo adminInfo, WorkerIdentifier workerId, final int startIndex, final int max, final QueryCriteria qc, final boolean includeData, final Map<String, Object> params) throws
            InvalidWorkerIdException,
            AuthorizationDeniedException,
            CryptoTokenOfflineException,
            QueryException,
            InvalidAlgorithmParameterException,
            UnsupportedCryptoTokenParameter,
            OperationUnsupportedException;
    
    /**
     * Checks if key generation is disabled in the deployment configuration.
     * @return true if key generation has been disabled globally.
     */
    boolean isKeyGenerationDisabled();
}
