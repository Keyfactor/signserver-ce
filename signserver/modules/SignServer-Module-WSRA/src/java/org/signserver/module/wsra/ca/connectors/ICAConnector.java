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
 
package org.signserver.module.wsra.ca.connectors;

import java.net.ConnectException;
import java.util.List;
import java.util.Properties;

import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.module.wsra.ca.ICertRequestData;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.validationservice.common.ICertificate;
import org.signserver.validationservice.common.Validation;

/**
 * Interface that all CA connectors must implement.
 * 
 * A CA connector is in charge of managing certificate
 * request and revocation towards different CAs.
 * 
 * 
 * 
 * @author Philip Vendil 18 okt 2008
 *
 * @version $Id$
 */

public interface ICAConnector {
	
	/**
	 * Initialization method that should be called directly after creation.
	 * @param workerId the unique id of the worker
	 * @param cAConnectorId the id of this CA Connector, a positive integer.
	 * @param props a subset of the worker properties only containing this CA connector properties, 
	 * for instance worker1.ca1.propkey will show up as property key 'propkey' in this properties
	 * @param ct the crypto token used by the ca connector.
	 * @throws SignServerException if unexpected error occurred during initialization.
	 */
	void init(int workerId, int cAConnectorId, Properties props, ICryptoToken ct) throws SignServerException;
	
	/**
	 * Method that returns a list of unique isserDNs that 
	 * this connector supports. Usually taken from the worker configuration.
	 * @return a list of issuer DNs that this CA connector can manage, never null.
	 */
	List<String> getSupportedIssuerDN();

	/**
	 * Method used to revoke a specified certificate for a specified
	 * issuer DN.
	 * 
	 * Important the framework may call this call with REVOKATION_REASON_NOT_REVOKED
	 * which means that the certificate should be unrevoked of current status is
	 * REVOKATION_REASON_CERTIFICATEHOLD
	 * 
	 * @param cert certificate to revoke.
	 * @param reason revoke reason, one of WSRAConstants.REVOKATION_REASON constants.
	 * @throws SignServerException for general failure exception.
	 * @throws AlreadyRevokedException if a certificate already is permanetly revoked.
	 * @throws IllegalRequestException if the request data in incorrect, this could be
	 * the case of unrevoke is called on a certificate that is not "ON HOLD",
	 */
	void revokeCertificate(ICertificate cert, int reason) throws AlreadyRevokedException, IllegalRequestException, SignServerException;

	/**
	 * Method used to request a certificate from the issuer according
	 * to the data in the request.
	 * 
	 * @param certReqData the request data.
	 * @return a generated certificate.
	 * @throws SignServerException if communication or other internal problems
	 * happened.
	 * @throws IllegalRequestException if the data in the request was invalid.
	 */
	ICertificate requestCertificate(ICertRequestData certReqData) throws IllegalRequestException, SignServerException;

	/**
	 * Method used to check the current status of a certificate.
	 * 
	 * @param certificate the certificate to check status of.
	 * @return the status of the current certificate or null if given certificate wasn't found for that issuer
	 * @throws SignServerException for general failure exception.
	 */
	Validation getCertificateStatus(ICertificate certificate) throws SignServerException;
	
	/**
	 * Method that should return the CA certificate chain of the 
	 * specified issuer. The Root CA should be last in the list and then
	 * ordered.
	 * @param issuerDN the isserDN of to look up.
	 * @return the certificate chain of the specified issuer.
	 * @throws SignServerException for general failure exception.
	 */
	List<ICertificate> getCACertificateChain(String issuerDN) throws SignServerException;

	/**
	 * Optional method used to test the connection to a specific underlying CA connector implementation.
	 * 
	 * @throws ConnectException if connection to underlying CA connector implementation failed.
	 * @throws SignServerException for general failure exception.
	 */
	void testConnection() throws ConnectException, SignServerException;

}
