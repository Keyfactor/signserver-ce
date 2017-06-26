/* ====================================================================
   Licensed to the Apache Software Foundation (ASF) under one or more
   contributor license agreements.  See the NOTICE file distributed with
   this work for additional information regarding copyright ownership.
   The ASF licenses this file to You under the Apache License, Version 2.0
   (the "License"); you may not use this file except in compliance with
   the License.  You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
==================================================================== 

 * Copyright (c) 2006, Wygwam
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met: 
 * 
 * - Redistributions of source code must retain the above copyright notice, 
 * this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice, 
 * this list of conditions and the following disclaimer in the documentation and/or 
 * other materials provided with the distribution.
 * - Neither the name of Wygwam nor the names of its contributors may be 
 * used to endorse or promote products derived from this software without 
 * specific prior written permission. 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY 
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES 
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
 * IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT 
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.openxml4j.opc.signature;

import java.security.Key;
import java.security.KeyException;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;

import org.openxml4j.exceptions.InvalidFormatException;
import org.openxml4j.opc.PackagePart;
import org.openxml4j.opc.PackageRelationshipCollection;
import org.openxml4j.opc.PackageRelationshipTypes;
import org.openxml4j.opc.PackagingURIHelper;

/**
 * implementation of KeySelector for OPC
 * 
 * @author aziz.goktepe (aka rayback_2)
 * 
 * patch originally created for SignServer project {@link http://www.signserver.org}
 * 
 */
public class OPCKeySelector extends KeySelector implements KeySelectorResult {

	private X509Certificate signingCertificate;

	private PackageDigitalSignature packageDigitalSignature;

	private PublicKey signingPublicKey;

	public OPCKeySelector(PackageDigitalSignature pPackageDigitalSignature) {
		this.packageDigitalSignature = pPackageDigitalSignature;
	}

	/**
	 * returns signing certificate if found
	 * 
	 * @return
	 */
	public X509Certificate getSigningCertificate() {
		return signingCertificate;
	}

	/**
	 * returns package digital signature object associated with this keyselector
	 * 
	 */
	public PackageDigitalSignature getPackageDigitalSignature() {
		return this.packageDigitalSignature;
	}

	/**
	 * 
	 * @return public key of signer. If getSigningCertificate() is not null ,
	 *         this is the public key of certificate found in package from
	 *         certificate part , or from x509Data inside signature xml.
	 * 
	 *         If getSigningCertificate() is null, this is public key found from
	 *         KeyValue from KeyInfo of in signature xml.
	 */
	public PublicKey getSigningPublicKey() {
		return signingPublicKey;
	}

	@Override
	/*
	 * tries to find signing certificate by looking into X509Data inside the
	 * signature (CertificateEmbeddingOption.IN_SIGNATURE_PART) if it can't find
	 * certificate in x509data then it looks for certificate part by following
	 * relationships from digital signature part
	 * (CertificateEmbeddingOption.IN_CERTIFICATE_PART) if it can't find both of
	 * above then it retrieves public key from KeyValue
	 * (CertificateEmbeddingOption.NOT_EMBEDDED)
	 */
	public KeySelectorResult select(KeyInfo keyInfo, Purpose purpose,
			AlgorithmMethod method, XMLCryptoContext context)
			throws KeySelectorException {

		SignatureMethod signatureMethod = (SignatureMethod) method;
		X509Certificate cert = null;

		// try to get certificate from x509data
		cert = tryGetSigningCertificateFromX509Data(keyInfo, signatureMethod);
		if (cert != null) {
			this.signingCertificate = cert;
			this.signingPublicKey = cert.getPublicKey();
			return this;
		}

		// try to get certificate from certificate part
		cert = tryGetSigningCertificateFromCertificatePart(signatureMethod);
		if (cert != null) {
			this.signingCertificate = cert;
			this.signingPublicKey = cert.getPublicKey();
			return this;
		}

		// try get public key from KeyValue
		final PublicKey pKey = getPublicKeyFromKeyInfo(keyInfo, signatureMethod);
		if (pKey != null) {
			this.signingPublicKey = pKey;
			return this;
		}

		return null;
	}

	/**
	 * retrieves public key from KeyValue
	 * (CertificateEmbeddingOption.NOT_EMBEDDED)
	 * 
	 * @return PublicKey if found, null otherwise
	 * @throws KeySelectorException
	 */
	private PublicKey getPublicKeyFromKeyInfo(KeyInfo keyInfo,
			SignatureMethod method) throws KeySelectorException {

		for (Object o1 : keyInfo.getContent()) {
			if (o1 instanceof KeyValue) {
				KeyValue data = (KeyValue) o1;
				PublicKey retVal;
				try {
					retVal = data.getPublicKey();
				} catch (KeyException e) {
					throw new KeySelectorException(e);
				}

				// check if algorithm fits
				if (!matchingAlgorithms(retVal.getAlgorithm(), method
						.getAlgorithm())) {
					throw new KeySelectorException(
							"algorithm specified by public key found in KeyValue is not supported. Specified algorithm is : "
									+ retVal.getAlgorithm());
				}
			}
		}

		return null;
	}

	/**
	 * tries to find signing certificate by looking into X509Data inside the
	 * signature (CertificateEmbeddingOption.IN_SIGNATURE_PART)
	 * 
	 * @param method
	 * @return signing Certificate if found, null otherwise
	 * @throws KeySelectorException
	 */
	private X509Certificate tryGetSigningCertificateFromX509Data(
			KeyInfo keyInfo, SignatureMethod method)
			throws KeySelectorException {

		// find all certificates in x509data
		List<X509Certificate> foundCerts = new ArrayList<X509Certificate>();

		for (Object o1 : keyInfo.getContent()) {
			if (o1 instanceof X509Data) {
				X509Data data = (X509Data) o1;
				for (Object o2 : data.getContent()) {
					if (o2 instanceof X509Certificate) {
						X509Certificate cert = (X509Certificate) o2;
						if (matchingAlgorithms(cert.getPublicKey()
								.getAlgorithm(), method.getAlgorithm())) {
							foundCerts.add(cert);
						}
					}
				}
			}
		}

		if (foundCerts.size() == 0) {
			// x509 data contains no certificate
			return null;
		} else if (foundCerts.size() == 1) {
			// we got only one certificate so it is our signing certificate
			X509Certificate cert = (X509Certificate) foundCerts.get(0);

			// check if algorithm fits
			if (!matchingAlgorithms(cert.getPublicKey().getAlgorithm(), method
					.getAlgorithm())) {
				throw new KeySelectorException(
						"algorithm specified by signing certificate is not supported. Certificate specified algorithm is : "
								+ cert.getPublicKey().getAlgorithm());
			}

			return cert;
		} else {
			// we found several certificates in x509 data
			// it must be certificate chain we have at hand. sort chain and
			// return signing certificate
			ArrayList<X509Certificate> sortedCerts;
			try {
				sortedCerts = sortCerts(foundCerts);
			} catch (InvalidFormatException e) {
				throw new KeySelectorException(e);
			}
			// after sorting chain the first certificate is our signing
			// certificate

			X509Certificate cert = sortedCerts.get(0);

			// check if algorithm fits
			if (!matchingAlgorithms(cert.getPublicKey().getAlgorithm(), method
					.getAlgorithm())) {
				throw new KeySelectorException(
						"algorithm specified by signing certificate is not supported. Certificate specified algorithm is : "
								+ cert.getPublicKey().getAlgorithm());
			}

			return cert;
		}
	}

	/**
	 * looks for certificate part by following relationships from digital
	 * signature part (CertificateEmbeddingOption.IN_CERTIFICATE_PART)
	 * 
	 * @param signatureMethod
	 * @return signing Certificate if found, null otherwise
	 * @throws KeySelectorException
	 */
	private X509Certificate tryGetSigningCertificateFromCertificatePart(
			SignatureMethod signatureMethod) throws KeySelectorException {
		// see if there's a relationship of type certificate from this part
		PackageRelationshipCollection certRels = null;
		try {
			certRels = this
					.getPackageDigitalSignature()
					.getSignaturePart()
					.getRelationshipsByType(
							PackageRelationshipTypes.DIGITAL_SIGNATURE_CERTIFICATE);
		} catch (InvalidFormatException e) {
			throw new KeySelectorException(e);
		}

		if (certRels != null && certRels.size() > 0) {
			// we found relationship to certificate part

			// if there's one relationship of a kind then it should be our
			// signing
			// certificate [M6.4]
			if (certRels.size() == 1) {
				try {
					CertificateFactory cf = CertificateFactory.getInstance(
							"X.509", "BC");

					PackagePart certPart = null;
					certPart = this.getPackageDigitalSignature()
							.getSignaturePart().getPackage().getPart(
									PackagingURIHelper.createPartName(certRels
											.iterator().next().getTargetURI()));
					X509Certificate cert = (X509Certificate) cf
							.generateCertificate(certPart.getInputStream());

					// check if algorithm fits
					if (!matchingAlgorithms(cert.getPublicKey().getAlgorithm(),
							signatureMethod.getAlgorithm())) {
						throw new KeySelectorException(
								"algorithm specified by signing certificate is not supported. Certificate specified algorithm is : "
										+ cert.getPublicKey().getAlgorithm());
					}

					return cert;

				} catch (Exception e) {
					throw new KeySelectorException(e);
				}
			} else {
				// standard does not say what to do if more than one
				// relationship of
				// a kind exist so we throw exception
				// TODO :check
				throw new KeySelectorException(
						"multiple relationships found from signature part to certificate parts.");
			}

		}

		return null;
	}

	private boolean matchingAlgorithms(String keyAlg, String signAlg) {
		if ("RSA".equalsIgnoreCase(keyAlg)) {
			return SignatureMethod.RSA_SHA1.equalsIgnoreCase(signAlg);
		} else if ("DSA".equalsIgnoreCase(keyAlg)) {
			return SignatureMethod.DSA_SHA1.equalsIgnoreCase(signAlg);
		} else if ("ECDSA".equalsIgnoreCase(keyAlg)) {
			return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1"
					.equals(signAlg);
		}
		return false;
	}

	/**
	 * Method sorting the certificate with the root certificate last.
	 * 
	 * @param icerts
	 *            ICertificates
	 * @return
	 * @throws InvalidFormatException
	 */
	private ArrayList<X509Certificate> sortCerts(List<X509Certificate> icerts)
			throws InvalidFormatException {
		ArrayList<X509Certificate> retval = new ArrayList<X509Certificate>();

		// Start with finding root
		X509Certificate currentCert = null;
		for (X509Certificate icert : icerts) {

			if (icert.getIssuerDN().equals(icert.getSubjectDN())) {
				retval.add(0, icert);
				currentCert = icert;
				break;
			}
		}
		icerts.remove(currentCert);

		if (retval.size() == 0) {
			throw new InvalidFormatException(
					"Error in certificate chain, no root certificate found in chain");
		}

		int tries = 10;
		while (icerts.size() > 0 && tries > 0) {
			for (X509Certificate icert : icerts) {
				if (currentCert.getSubjectDN().equals(icert.getIssuerDN())) {
					retval.add(0, icert);
					currentCert = icert;
					break;
				}
			}
			icerts.remove(currentCert);
			tries--;

			if (tries == 0) {
				throw new InvalidFormatException(
						"Error constructing a complete ca certificate chain from retrieved certificates");
			}
		}

		return retval;
	}

	@Override
	public Key getKey() {
		return this.getSigningPublicKey();
	}
}
