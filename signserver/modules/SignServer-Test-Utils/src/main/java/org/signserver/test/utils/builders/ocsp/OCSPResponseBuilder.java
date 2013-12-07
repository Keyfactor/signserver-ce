/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.test.utils.builders.ocsp;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CertBuilderException;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.test.utils.builders.ocsp.OCSPResponse.Error;

/**
 * Builds an OCSP response.
 *
 * XXX: This code is duplicated in EJBCA and SignServer. Consider breaking out as a separate JAR.
 *
 * @version $Id$
 */
public class OCSPResponseBuilder {
    
    private JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
    
    private String responderName;
    private String signatureAlgorithm;
    private PrivateKey issuerPrivateKey;
    private Date producedAt;
    private X509CertificateHolder[] chain;
    
    private Set<OcspRespObject> responses = new HashSet<OcspRespObject>();
    
    private OCSPResponseStatus responseStatus;
    
    // TODO: All of the below might not be needed. Consider refactoring
    private Long responseTime;
    private Integer httpReturnCode;
    private OCSPResponse.Error responseError;
    private X500Principal responseIssuerDN;
    private X509Certificate responseSignerCertificate;
    private List<String> failedResponses;
    private List<String> responsesFromOther;
    
    private boolean noResponse;
    private byte[] nonce;
    private Set<OcspExt> extensions = new HashSet<OcspExt>();
    
    private BasicOCSPResp buildBasicOCSPResp() throws OCSPResponseBuilderException {
        try {
            BasicOCSPRespBuilder gen = new BasicOCSPRespBuilder(new RespID(new X500Name(getResponderName())));
            
            if (getNonce() != null) {
                extensions.add(new OcspExt(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(nonce)));
            }
            
            Extension[] extArray = new Extension[extensions.size()];
            int i = 0;
            for (OcspExt ext : extensions) {
                extArray[i++] = new Extension(ext.getOid(), ext.isIsCritical(), ext.getValue());
            }
            if (extArray.length > 0) {
                gen.setResponseExtensions(new Extensions(extArray));
            }
            
            for (OcspRespObject r : responses) {
                gen.addResponse(r.getCertId(), r.getCertStatus(), r.getThisUpdate(), r.getNextUpdate(), r.getExtensions());
            }
            
            ContentSigner contentSigner = /*new BufferingContentSigner(*/new JcaContentSignerBuilder(getSignatureAlgorithm()).setProvider("BC").build(getIssuerPrivateKey());//, 20480);
            
            BasicOCSPResp response = gen.build(contentSigner, getChain(), getProducedAt());
            return response;
        } catch (OCSPException ex) {
            throw new OCSPResponseBuilderException(ex);
        } catch (NoSuchAlgorithmException ex) {
            throw new OCSPResponseBuilderException(ex);
        } catch (NoSuchProviderException ex) {
            throw new OCSPResponseBuilderException(ex);
        } catch (OperatorCreationException ex) {
            throw new OCSPResponseBuilderException(ex);
        }
    }
  
    /**
     * Builds the OCSP response based on the provided values and using the 
     * default values for other.
     * @return the new OCSP response
     * @throws OCSPResponseBuilderException in case of any error
     */
    public OCSPResponse build() throws OCSPResponseBuilderException {
        final OCSPResponse result = new OCSPResponse();
        try {
            result.setError(getResponseError());
            result.setFailedResponses(getFailedResponses());
            result.setResponsesFromOther(getResponsesFromOther());
            result.setHttpReturnCode(getHttpReturnCode());
            result.setResponseTime(getResponseTime());
            
            if (!isNoResponse()) {
                result.setIssuerDN(getResponseIssuerDN());
                result.setSignerCertificate(getResponseSignerCertificate());
            
                OCSPRespBuilder resBuilder = new OCSPRespBuilder();

                BasicOCSPResp responseObject = buildBasicOCSPResp();
                result.setResponseObject(responseObject);

                OCSPResp resp = resBuilder.build(getResponseStatus().getValue().intValue(), responseObject);
                result.setResp(resp);
            }
            
            return result;
        } catch (CertBuilderException ex) {
            throw new OCSPResponseBuilderException(ex);
        } catch (CertificateException ex) {
            throw new OCSPResponseBuilderException(ex);
        } catch (OCSPException ex) {
            throw new OCSPResponseBuilderException(ex);
        }
    }

    public Set<OcspRespObject> getResponses() {
        return responses;
    }

    public OCSPResponseBuilder addResponse(OcspRespObject response) {
        responses.add(response);
        return this;
    }
    
    public String getSignatureAlgorithm() {
        if (signatureAlgorithm == null) {
            signatureAlgorithm = "SHA1withRSA";
        }
        return signatureAlgorithm;
    }

    public OCSPResponseBuilder setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }
    
    public PrivateKey getIssuerPrivateKey() throws NoSuchAlgorithmException, NoSuchProviderException {
        if (issuerPrivateKey == null) {
            issuerPrivateKey = CryptoUtils.generateRSA(768).getPrivate();
        }
        return issuerPrivateKey;
    }

    public OCSPResponseBuilder setIssuerPrivateKey(PrivateKey issuerPrivateKey) {
        this.issuerPrivateKey = issuerPrivateKey;
        return this;
    }
    
    public Date getProducedAt() {
        if (producedAt == null) {
            producedAt = new Date();
        }
        return producedAt;
    }

    public OCSPResponseBuilder setProducedAt(Date producedAt) {
        this.producedAt = producedAt;
        return this;
    }

    public X509CertificateHolder[] getChain() {
        return chain;
    }

    public OCSPResponseBuilder setChain(X509CertificateHolder[] chain) {
        this.chain = chain;
        return this;
    }

    public String getResponderName() {
        if (responderName == null) {
            responderName = "CN=Responder 1";
        }
        return responderName;
    }

    public void setResponderName(String responderName) {
        this.responderName = responderName;
    }

    public OCSPResponseStatus getResponseStatus() {
        if (responseStatus == null) {
            responseStatus = new OCSPResponseStatus(OCSPResponseStatus.SUCCESSFUL);
        }
        return responseStatus;
    }

    public OCSPResponseBuilder setResponseStatus(OCSPResponseStatus responseStatus) {
        this.responseStatus = responseStatus;
        return this;
    }

    public List<String> getFailedResponses() {
        if (failedResponses == null) {
            failedResponses = Collections.emptyList();
        }
        return failedResponses;
    }

    public OCSPResponseBuilder setFailedResponses(List<String> failedResponses) {
        this.failedResponses = failedResponses;
        return this;
    }

    public List<String> getResponsesFromOther() {
        if (responsesFromOther == null) {
            responsesFromOther = Collections.emptyList();
        }
        return responsesFromOther;
    }

    public OCSPResponseBuilder setResponsesFromOther(List<String> responsesFromOther) {
        this.responsesFromOther = responsesFromOther;
        return this;
    }

    public int getHttpReturnCode() {
        if (httpReturnCode == null) {
            httpReturnCode = 200;
        }
        return httpReturnCode;
    }

    public OCSPResponseBuilder setHttpReturnCode(int httpReturnCode) {
        this.httpReturnCode = httpReturnCode;
        return this;
    }

    public Error getResponseError() {
        if (responseError == null) {
            responseError = Error.responseSuccess;
        }
        return responseError;
    }

    public OCSPResponseBuilder setResponseError(Error responseError) {
        this.responseError = responseError;
        return this;
    }

    public X500Principal getResponseIssuerDN() { // TODO: redundant?
        if (responseIssuerDN == null) {
            responseIssuerDN = new X500Principal("CN=Responder 1");
        }
        return responseIssuerDN;
    }

    public OCSPResponseBuilder setResponseIssuerDN(X500Principal responseIssuerDN) {
        this.responseIssuerDN = responseIssuerDN;
        return this;
    }

    public X509Certificate getResponseSignerCertificate() throws CertBuilderException, CertificateException {
        if (responseSignerCertificate == null) {
            responseSignerCertificate = converter.getCertificate(new CertBuilder().setSubject(getResponseIssuerDN().getName()).build());
        }
        return responseSignerCertificate;
    }

    public OCSPResponseBuilder setResponseSignerCertificate(X509Certificate responseSignerCertificate) {
        this.responseSignerCertificate = responseSignerCertificate;
        return this;
    }

    public Long getResponseTime() {
        if (responseTime == null) {
            responseTime = 4711000L;
        }
        return responseTime;
    }

    public OCSPResponseBuilder setResponseTime(Long responseTime) {
        this.responseTime = responseTime;
        return this;
    }

    public boolean isNoResponse() {
        return noResponse;
    }

    public OCSPResponseBuilder setNoResponse(boolean noResponse) {
        this.noResponse = noResponse;
        return this;
    }

    public byte[] getNonce() {
        return nonce;
    }

    public OCSPResponseBuilder setNonce(byte[] nonce) {
        this.nonce = nonce;
        return this;
    }
    
    public OCSPResponseBuilder addExtension(OcspExt extension) {
        this.extensions.add(extension);
        return this;
    }
    
    public OCSPResponseBuilder addExtensions(Collection<? extends OcspExt> extensions) {
        this.extensions.addAll(extensions);
        return this;
    }
    
}
