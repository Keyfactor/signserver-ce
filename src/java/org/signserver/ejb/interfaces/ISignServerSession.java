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
import org.signserver.common.ISignRequest;
import org.signserver.common.ISignResponse;
import org.signserver.common.ISignerCertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalSignRequestException;
import org.signserver.common.InvalidSignerIdException;
import org.signserver.common.SignTokenAuthenticationFailureException;
import org.signserver.common.SignTokenOfflineException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;

public interface ISignServerSession  {

	/**
	 * The SignSession Beans main method. Takes signature requests processes them
	 * and returns a response.
	 *
	 *     
	 * @throws SignTokenOfflineException if the signers token isn't activated. 
	 * @throws IllegalSignRequestException if illegal request is sent to the method
	 */
	ISignResponse signData(int signerId, ISignRequest request,
			X509Certificate clientCert, String requestIP)
			throws IllegalSignRequestException, SignTokenOfflineException;

	/**
	 * Returns the current status of a signers. 
	 *
	 * Should be used with the cmd-line status command.
	 * @param signerId of the signer
	 * @return a SignerStatus class 
	 *  
	 */
	WorkerStatus getStatus(int workerId) throws InvalidSignerIdException;

	/**
	 * Returns the Id of a signer given a name 
	 *
	 * @param signerName of the signer cannot be null
	 * @return The Id of a named signer or 0 if no such name exists
	 *  
	 */
	int getSignerId(String signerName);

	/**
	 * Method used when a configuration have been updated. And should be
	 * called from the commandline.
	 *	  
	 *
	 * @param workerId of the worker that should be reloaded, or 0 to reload
	 * reload of all available workers 
	 */
	void reloadConfiguration(int workerId);

	/**
	 * Method used to activate the signtoken of a signer.
	 * Should be called from the command line.
	 *    
	 * 
	 * @param signerId of the signer
	 * @param authenticationCode (PIN) used to activate the token.
	 * 
	 * @throws SignTokenOfflineException 
	 * @throws SignTokenAuthenticationFailureException 
	 *
	 */
	void activateSigner(int signerId, String authenticationCode)
			throws SignTokenAuthenticationFailureException,
			SignTokenOfflineException, InvalidSignerIdException;

	/**
	 * Method used to deactivate the signtoken of a signer.
	 * Should be called from the command line.
	 *    
	 * 
	 * @param signerId of the signer
	 * @param authenticationCode (PIN) used to activate the token.
	 * @return true if deactivation was successful
	 * @throws SignTokenOfflineException 
	 * @throws SignTokenAuthenticationFailureException 
	 *
	 */
	boolean deactivateSigner(int signerId) throws SignTokenOfflineException,
			InvalidSignerIdException;

	/**
	 * Returns the current configuration of a signer.
	 * 
	 * Observe that this config might not be active until a reload command have been excecuted.
	 * 
	 * 
	 * @param signerId
	 * @return the current (not always active) configuration
	 * 
	 */
	WorkerConfig getCurrentSignerConfig(int signerId);

	/**
	 * Sets a parameter in a workers configuration
	 * 
	 * Observe that the worker isn't activated with this config until reload is performed.
	 * 
	 * @param workerId
	 * @param key
	 * @param value
	 * 
	 */
	void setWorkerProperty(int workerId, String key, String value);

	/**
	 * Removes a given workers property
	 * 
	 * 
	 * @param workerId
	 * @param key
	 * @return true if the property did exist and was removed othervise false
	 * 
	 */
	boolean removeWorkerProperty(int workerId, String key);

	/**
	 * Method that returns a collection of AuthorizedClient of
	 * client certificate sn and issuerid accepted for a given signer-
	 * 
	 * @param signerId
	 * @return Sorted collection of authorized clients
	 * 
	 */
	Collection<AuthorizedClient> getAuthorizedClients(int signerId);

	/**
	 * Method adding an authorized client to a signer
	 * 
	 * @param signerId
	 * @param authClient
	 * 
	 */
	void addAuthorizedClient(int signerId, AuthorizedClient authClient);

	/**
	 * Removes an authorized client from a signer
	 * 
	 * @param signerId
	 * @param authClient
	 * 
	 */
	boolean removeAuthorizedClient(int signerId, AuthorizedClient authClient);

	/**
	 * Method used to let a signer generate a certificate request
	 * using the signers own genCertificateRequest method
	 * 
	 * @param signerId id of the signer
	 * @param certReqInfo information used by the signer to create the request
	 * 
	 */
	ISignerCertReqData getCertificateRequest(int signerId,
			ISignerCertReqInfo certReqInfo) throws SignTokenOfflineException,
			InvalidSignerIdException;

	/**
	 * Method used to remove a key from a signer.
	 * 
	 * @param signerId id of the signer
	 * @param purpose on of ISignToken.PURPOSE_ constants
	 * @return true if removal was successful.
	 * 
	 */
	boolean destroyKey(int signerId, int purpose)
			throws InvalidSignerIdException;

	/**
	 * Method used to upload a certificate to a signers active configuration
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
	 * Methods that generates a free worker id that can be used for new signers
	 */
	int genFreeWorkerId();

	/**
	 * Method that finds an archive given it's archive Id
	 * 
	 * @param signerId id of the signer
	 * @param archiveId the Id of the archive data (could be request serialnumber).
	 * @return the ArchiveDataVO or null if it wasn't found.
	 */
	ArchiveDataVO findArchiveDataFromArchiveId(int signerId, String archiveId);

	/**
	 * Method that finds an archive given it's requesters IP
	 * 
	 * @param signerId id of the signer
	 * @param requestIP the IP address of the client creating the request
	 * 
	 */
	List<ArchiveDataVO> findArchiveDatasFromRequestIP(int signerId,
			String requestIP);

	/**
	 * Method that finds an archive given it's requesters client certificate
	 * 
	 * @param signerId id of the signer
	 * @param requestCertSerialnumber the serialnumber of the certificate making the request
	 * @param requestIssuerDN the issuer of the client certificate
	 * 
	 */
	List<ArchiveDataVO> findArchiveDatasFromRequestCertificate(int signerId,
			BigInteger requestCertSerialnumber, String requestCertIssuerDN);

	@Remote 
	public interface IRemote extends ISignServerSession {
		public static final String JNDI_NAME = "signserver/SignServerSessionBean/remote";
	}

	@Local 
	public interface ILocal extends ISignServerSession {
		public static final String JNDI_NAME = "signserver/SignServerSessionBean/local";
	}
}