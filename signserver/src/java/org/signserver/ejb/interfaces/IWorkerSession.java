package org.signserver.ejb.interfaces;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import javax.ejb.Local;
import javax.ejb.Remote;

import org.signserver.common.ArchiveDataVO;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;

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
     */
    ICertReqData getCertificateRequest(int signerId,
            ISignerCertReqInfo certReqInfo) throws CryptoTokenOfflineException,
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
     * Method used to remove a key from a signer.
     *
     * @param signerId id of the signer
     * @param purpose on of ICryptoToken.PURPOSE_ constants
     * @return true if removal was successful.
     */
    boolean destroyKey(int signerId, int purpose)
            throws InvalidWorkerIdException;

    /**
     * Method used to upload a certificate to a signers active configuration.
     *
     * @param signerId id of the signer
     * @param signerCert the certificate used to sign signature requests
     * @param scope one of GlobalConfiguration.SCOPE_ constants
     */
    void uploadSignerCertificate(int signerId, X509Certificate signerCert,
            String scope);

    /**
     * Method used to upload a complete certificate chain to a configuration
     *
     * @param signerId id of the signer
     * @param signerCerts the certificate chain used to sign signature requests
     * @param scope one of GlobalConfiguration.SCOPE_ constants
     */
    void uploadSignerCertificateChain(int signerId,
            Collection<Certificate> signerCerts, String scope);

    /**
     * Methods that generates a free worker id that can be used for new signers.
     */
    int genFreeWorkerId();

    /**
     * Method that finds an archive given it's archive Id.
     *
     * @param signerId id of the signer
     * @param archiveId the Id of the archive data (could be request
     * serialnumber).
     * @return the ArchiveDataVO or null if it wasn't found.
     */
    ArchiveDataVO findArchiveDataFromArchiveId(int signerId, String archiveId);

    /**
     * Method that finds an archive given it's requesters IP.
     *
     * @param signerId id of the signer
     * @param requestIP the IP address of the client creating the request
     */
    List<ArchiveDataVO> findArchiveDatasFromRequestIP(int signerId,
            String requestIP);

    /**
     * Method that finds an archive given it's requesters client certificate.
     *
     * @param signerId id of the signer
     * @param serialNumber the serialnumber of the certificate
     * making the request
     * @param issuerDN the issuer of the client certificate
     */
    List<ArchiveDataVO> findArchiveDatasFromRequestCertificate(int signerId,
            BigInteger serialNumber, String issuerDN);

    @Remote
    interface IRemote extends IWorkerSession {

        String JNDI_NAME = "signserver/WorkerSessionBean/remote";
    }

    @Local
    interface ILocal extends IWorkerSession {

        String JNDI_NAME = "signserver/WorkerSessionBean/local";
    }
}
