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

package org.signserver.common;

import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.List;

import org.apache.log4j.Logger;
import org.signserver.validationservice.common.ICertificate;
import org.signserver.validationservice.common.ValidateResponse;
import org.signserver.validationservice.common.Validation;

/**
 * A generic response class for validation results.
 * 
 * The {@link GenericValidationResponse#isValid()} method can be used to see 
 * if the document was found valid. 
 * 
 * @author Markus Kilås
 * @version $Id$
 */

public class GenericValidationResponse extends ProcessResponse {

	private static final long serialVersionUID = 1L;
	private transient Logger log = Logger.getLogger(this.getClass());

	private int requestID = 0;
	private boolean valid = false;
	private ValidateResponse certificateValidateResponse;
        private byte[] processedData;

	/**
	 * Default constructor used during serialization
	 */
	public GenericValidationResponse() { }

	/**
	 * Constructs a new GenericValidagtionResponse
	 * 
	 * @param requestID The request id
	 * @param valid True if the validated document was found valid
	 * @param certificateValidateResponse The results from validating the certificate
         * @param processedData For instance the validated document or some modification of it
	 */
	public GenericValidationResponse(int requestID, boolean valid, ValidateResponse certificateValidateResponse, byte[] processedData) {
		this.requestID = requestID;
		this.valid = valid;
		this.certificateValidateResponse = certificateValidateResponse;
                this.processedData = processedData;
	}

        /**
	 * Constructs a new GenericValidagtionResponse
	 *
	 * @param requestID The request id
	 * @param valid True if the validated document was found valid
	 * @param certificateValidateResponse The results from validating the certificate
	 */
	public GenericValidationResponse(int requestID, boolean valid, ValidateResponse certificateValidateResponse) {
            this(requestID, valid, certificateValidateResponse, null);
	}

	/**
	 * Constructs a new GenericValidagtionResponse
	 * 
	 * @param requestID The request id
	 * @param valid True if the validated document was found valid
	 */
	public GenericValidationResponse(int requestID, boolean valid) {
		this(requestID, valid, null);
	}

	/**
	 * 
	 * @see org.signserver.common.ProcessResponse#getRequestID()
	 */
	public int getRequestID() {
		return requestID;
	}

	/**
	 * @return True if the document was valid.
	 */
	public boolean isValid() {
		return valid;
	}

	/**
	 * @return The certificate validation response or null if it could not be performed.
	 */
	public ValidateResponse getCertificateValidateResponse() {
		return certificateValidateResponse;
	}

	/**
	 * @return The signer's certificate or null if it could not be determined.
	 */
	public ICertificate getSignerCertificate() {
		if (certificateValidateResponse != null) {
			return certificateValidateResponse.getValidation().getCertificate();
		}
		return null;
	}

	/**
	 * @return The certificate validation result or null if it could not be performed.
	 */
	public Validation getCertificateValidation() {
		if (certificateValidateResponse != null) {
			return certificateValidateResponse.getValidation();
		}
		return null;
	}

	/**
	 * @return The CA certificate chain included in the document.
	 */
	public List<ICertificate> getCAChain() {
		if (certificateValidateResponse != null) {
			return certificateValidateResponse.getValidation().getCAChain();
		}
		return Collections.emptyList();
	}

        /**
         * @return Validator specific data (for instance the validated document) or null.
         */
        public byte[] getProcessedData() {
            return processedData;
        }

	/**
	 * Deserializes this object from an InputStream.
	 * 
	 * @param in InputStream to read from.
	 * @throws IOException If an I/O error occurred.
	 */
	public void parse(DataInput in) throws IOException {
		log.debug(">parse");
		in.readInt();
		this.requestID = in.readInt();
		this.valid = in.readBoolean();

                int responseSize = in.readInt();
		if (responseSize > 0) {
			this.certificateValidateResponse = new ValidateResponse();
			this.certificateValidateResponse.parse(in);
		} else {
			this.certificateValidateResponse = null;
		}
                int dataSize = in.readInt();
                log.debug("dataSize: " + responseSize);
                this.processedData = new byte[dataSize];
                in.readFully(this.processedData);
		log.debug("<parse");
	}

	/**
	 * Serializes this object and writes it to an DataOutput.
	 * 
	 * @param out DataOutput to write to.
	 * @throws IOException If an I/O error occurred.
	 * @throws IllegalArgumentException If the method was not called with an InputStream.
	 */
	public void serialize(DataOutput out) throws IOException {
		log.debug(">serlialize");
		out.writeInt(RequestAndResponseManager.RESPONSETYPE_GENERICVALIDATION);
		out.writeInt(this.requestID);
		out.writeBoolean(this.valid);

		if (certificateValidateResponse != null) {
                    ByteArrayOutputStream resOut = new ByteArrayOutputStream();
			certificateValidateResponse.serialize(new DataOutputStream(resOut));
                    out.writeInt(resOut.size());
                    log.debug("resOutSize: " + resOut.size());
                    out.write(resOut.toByteArray());
		} else {
                    out.writeInt(0);
                }

                if(processedData != null) {
                    out.writeInt(processedData.length);
                    log.debug("processedDataSize: " + processedData.length);
                    out.write(processedData);
                } else {
                    out.writeInt(0);
                }
		
		log.debug("<serialize");
	}

}
