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

package org.signserver.validationservice.server;

import java.util.List;

import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.validationservice.common.ICertificate;
import org.signserver.validationservice.common.ValidateRequest;
import org.signserver.validationservice.common.ValidateResponse;
import org.signserver.validationservice.common.Validation;
import org.signserver.validationservice.common.Validation.Status;

/**
 * Default validation service performing a full verification and iterating
 * between the configured validators for revocation status
 * 
 * 
 * @author Philip Vendil 29 nov 2007
 * 
 * @version $Id$
 */

public class DefaultValidationService extends BaseValidationService {

	/**
	 * @see org.signserver.validationservice.server.IValidationService#validate(org.signserver.validationservice.common.ValidateRequest)
	 */
	public ValidateResponse validate(ValidateRequest validationRequest)
			throws IllegalRequestException, CryptoTokenOfflineException,
			SignServerException {

		// Get Certificate Chain
		List<ICertificate> cAChain = getCertificateChain(validationRequest
				.getCertificate());

		if (cAChain == null) {
			Validation valRes = new Validation(validationRequest
					.getCertificate(), null,
					Validation.Status.ISSUERNOTSUPPORTED,
					"Issuer of given certificate isn't supported");
			return new ValidateResponse(valRes, null);
		}
		// Verify and check validity
		Validation validation = ICertificateManager.verifyCertAndChain(
				validationRequest.getCertificate(), cAChain);

		String[] validPurposes = null;
		if (validation.getStatus().equals(Status.VALID)) {

			// Check Certificate purposes
			if (validationRequest.getCertPurposes() != null
					&& (validPurposes = getCertPurposeChecker()
							.checkCertPurposes(
									validationRequest.getCertificate(),
									validationRequest.getCertPurposes())) == null) {
				validation = new Validation(
						validationRequest.getCertificate(),
						cAChain,
						Validation.Status.BADCERTPURPOSE,
						"Error certificate doesn't fulfill any of the specified certificate purposes in the request.");
			} else {
				// Check revocation of the certificate and for the entire chain.
				validation = validationCache.get(validationRequest
						.getCertificate());
				if (validation == null) {
					for (IValidator validator : validators.values()) {
						validation = validator.validate(validationRequest
								.getCertificate());
						if (validation != null) {
							validationCache.put(validationRequest
									.getCertificate(), validation);
							break;
						}
					}
				}

				if (validation == null) {
					throw new IllegalRequestException(
							"Error no validators in validation service "
									+ workerId
									+ " supports the issuer of given CA "
									+ validationRequest.getCertificate()
											.getIssuer());
				}
				// code below was used to walk through the certificate chain and
				// call validate on validator for each cert found in chain
				// it is not necessary though, since the validate called on the
				// requested certificate validates whole chain
				// if(validation.getStatus().equals(Validation.Status.VALID)){
				// for(ICertificate cacert : cAChain){
				// Validation cavalidation =
				// validationCache.get(validationRequest.getCertificate());
				// if(cavalidation == null){
				// for(IValidator validator : validators.values()){
				// cavalidation = validator.validate(cacert);
				// if(cavalidation != null){
				// validationCache.put(cacert, cavalidation);
				// break;
				// }
				// }
				// }
				// if(cavalidation == null){
				// throw new
				// IllegalRequestException("Error no validators in validation service "
				// + workerId + " supports the issuer of given CA " +
				// validationRequest.getCertificate().getIssuer());
				// }
				// if(cavalidation != null &&
				// !cavalidation.getStatus().equals(Validation.Status.VALID)){
				// validation = new
				// Validation(validationRequest.getCertificate(),cAChain,Validation.Status.CAREVOKED," Error CA issuing the requested certificate was revoked",cavalidation.getRevokedDate(),cavalidation.getRevokationReason());
				// break;
				// }
				// }
				// }
			}
		}

		return new ValidateResponse(validation, validPurposes);
	}

	/**
	 * Method returning the entire certificate chain for the given certificate
	 * from the configured validators.
	 * 
	 * @param certificate
	 *            to verify
	 * @return a certificate chain with the root CA last.
	 */
	private List<ICertificate> getCertificateChain(ICertificate certificate) {
		List<ICertificate> retval = null;
		for (IValidator validator : validators.values()) {
			retval = validator.getCertificateChain(certificate);
			if (retval != null) {
				break;
			}
		}
		return retval;
	}

}
