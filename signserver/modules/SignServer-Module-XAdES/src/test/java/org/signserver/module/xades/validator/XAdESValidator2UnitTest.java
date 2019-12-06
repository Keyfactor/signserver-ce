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
package org.signserver.module.xades.validator;

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.module.xades.signer.MockedXAdESSigner;
import org.signserver.module.xades.signer.XAdESSigner;
import org.signserver.module.xades.signer.XAdESSignerUnitTest;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CertExt;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.test.utils.builders.crl.CRLBuilder;
import org.signserver.validationservice.common.Validation;

import com.google.inject.Inject;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.cesecore.util.CertTools;
import org.junit.AfterClass;
import org.junit.Before;
import org.signserver.common.SignServerException;
import org.signserver.common.data.DocumentValidationRequest;
import org.signserver.common.data.DocumentValidationResponse;
import org.signserver.common.data.SignatureRequest;
import org.signserver.server.ServicesImpl;
import org.signserver.server.SignServerContext;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.test.utils.builders.ocsp.OCSPResponseBuilder;
import org.signserver.test.utils.builders.ocsp.OcspRespObject;
import org.signserver.test.utils.mock.MockedCryptoToken;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.validationservice.server.OCSPResponse;
import org.xml.sax.SAXParseException;

import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.MessageDigestEngineProvider;
import xades4j.providers.TimeStampTokenVerificationException;
import xades4j.providers.impl.DefaultTimeStampVerificationProvider;

/**
 * Additional unit tests for the XAdESValidator class.
 * 
 * This class set ups new certificate chains and signs and verifies a document
 * using it.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class XAdESValidator2UnitTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(XAdESSignerUnitTest.class);
    
    // Root CA
    private static KeyPair rootcaKeyPair;
    private static X509CertificateHolder rootcaCert;
    private static X509CRLHolder rootcaCRLEmpty;
    private static X509CRLHolder rootcaCRLSubCAAndSigner1Revoked;
    private static X509CRLHolder rootcaCRLSigner5Revoked;
    private static File rootcaCRLFile;
    
    // Sub CA 1
    private static X509CertificateHolder subca1Cert;
    private static X509CRLHolder subca1CRLEmpty;
    private static X509CRLHolder subca1CRLSigner2Revoked;
    private static File subca1CRLFile;
    
    // Sub CA 2
    private static KeyPair subca2KeyPair;
    private static X509CertificateHolder subca2Cert;
    
    // Other
    private static X509CRLHolder otherCRL;
    private static KeyPair anotherKeyPair;
    
    // Signer 1: Root CA, Signer
    private static MockedCryptoToken token1;
    private static String signedXml1;
    
    // Signer 2: Root CA, Sub CA, Signer
    private static MockedCryptoToken token2;
    private static String signedXml2;

    // Signer 3: Root CA, Signer including OCSP URI
    private static MockedCryptoToken token3;
    private static String signedXml3;
    private static X509CertificateHolder signer3Cert;
    
    // Signer 4: Root CA, Sub CA2 including OCSP URI, Signer including OCSP URI
    private static MockedCryptoToken token4;
    private static String signedXml4;
    private static X509CertificateHolder signer4Cert;
    
    // Signer 5: Root CA, Signer including OCSP URI and CDP
    private static MockedCryptoToken token5;
    private static String signedXml5;
    private static X509CertificateHolder signer5Cert;
    
    // OCSP Signer 1: Root CA, ocsp signer
    private static KeyPair ocspSigner1KeyPair;
    private static X509CertificateHolder ocspSigner1Cert;
    
    // OCSP Signer 2: Root CA, Sub CA 2, ocsp signer
    private static KeyPair ocspSigner2KeyPair;
    private static X509CertificateHolder ocspSigner2Cert;

    // hardcoded signed XML document with timestamp response
    private static String SIGNED_XML_FORM_T = 
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"xmldsig-42e9e098-2eb8-40ba-88ca-fd4b69af038a\">\n"
                +"<ds:SignedInfo>\n"
                +"<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>\n"
                +"<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n"
                +"<ds:Reference Id=\"xmldsig-42e9e098-2eb8-40ba-88ca-fd4b69af038a-ref0\" Type=\"http://www.w3.org/2000/09/xmldsig#Object\" URI=\"#xmldsig-42e9e098-2eb8-40ba-88ca-fd4b69af038a-object0\">\n"
                +"<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n"
                +"<ds:DigestValue>sRuh+wSYXq5wx5yabOKe5kk69VioHBgksJtR2JG5aMI=</ds:DigestValue>\n"
                +"</ds:Reference>\n"
                +"<ds:Reference Type=\"http://uri.etsi.org/01903#SignedProperties\" URI=\"#xmldsig-42e9e098-2eb8-40ba-88ca-fd4b69af038a-signedprops\">\n"
                +"<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n"
                +"<ds:DigestValue>SMzXP6aRX9dPYCQ2zewLnkHJ8/dmwhzq2enWGldMtPs=</ds:DigestValue>\n"
                +"</ds:Reference>\n"
                +"</ds:SignedInfo>\n"
                +"<ds:SignatureValue Id=\"xmldsig-42e9e098-2eb8-40ba-88ca-fd4b69af038a-sigvalue\">\n"
                +"gizkgI6Fxo87vn+PnEMwBi9P3zbKbiresmI4RtLoEBc0MLk0GYjlkcpB8xxHO4C30N7ue22eUngP\n"
                +"DtU0DelSkCwjl8OUHl9CJ9cjUHgJu1CCk8ZRee7WFwwNNk2DQZHz6QxF5L1SdvlDQQUstqd/tY5K\n"
                +"8YP5Zypn+g+VgsbGbQdR4V//9ZURKQDfsD402CHpSPsSFe8xkkUxQX0Kg/VlO8BqS6+55QRCR8SS\n"
                +"B7GL92x8vLSlfIbdP6XVpIQcoODUEJcURSqF1UurhKlHxxXJlsyznIzCwjJc5Of1rofaZvps+Sby\n"
                +"SFiALjKsgEvmV2B6kvQIQYP6dUg4Q03C483Ipg==\n"
                +"</ds:SignatureValue>\n"
                +"<ds:KeyInfo>\n"
                +"<ds:X509Data>\n"
                +"<ds:X509Certificate>\n"
                +"MIIElTCCAn2gAwIBAgIIBT9pktCBJIowDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJv\n"
                +"b3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYT\n"
                +"AlNFMB4XDTExMDUyNzA5NTAzN1oXDTIxMDUyNzA5NTAzN1owRzERMA8GA1UEAwwIU2lnbmVyIDIx\n"
                +"EDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIIBIjAN\n"
                +"BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAokJJPVkPrn3a55rO6A3Bnbe0nfJR9IDSI8AmFhYE\n"
                +"BLoKfiavx0oMdbdDe+Dkwv78xBkgbj//2lhMCVmss90RzY+d0d0rg2SP8y/DsyxwriqCfuM7lnlg\n"
                +"vSHCYwoX8+uDM7zI53ykKVhqI3ttyFPa8RsjfFOIWqf39++sJUheW4j9x9rutf6qgtjxOYPQwDyg\n"
                +"T9cIVpM7ZehhqVYlcQZRsprMg55s2SN/a78krAW51msoIDgd9+zbsIvzuGqCspO3AN8b2m8tlHTl\n"
                +"A/E4+3OZkSqgpx8FSKIfbKUa866pRzptvcbL/wpFxYkyxqcB6o7CFnWbr3gUPpz8KjuY7ypMmwID\n"
                +"AQABo38wfTAdBgNVHQ4EFgQUSkR/B71idJmR8deZziBAqSzWzhMwDAYDVR0TAQH/BAIwADAfBgNV\n"
                +"HSMEGDAWgBQgeiHe6K27Aqj7cVikCWK52FgFojAOBgNVHQ8BAf8EBAMCBeAwHQYDVR0lBBYwFAYI\n"
                +"KwYBBQUHAwIGCCsGAQUFBwMEMA0GCSqGSIb3DQEBCwUAA4ICAQA+pQuI1QmZLdheCVmc+k1h53uI\n"
                +"v9pBnBKSbKn0/CVznmlPOpJIwwuzcLfCesa6gkG6BabHJwMrU/SpZuWurHxdEKe6fS/ngYnIjFI5\n"
                +"R0Kgl1czqq/tXDjGEpv2x0tZECqLFrkC7a+gjXJPE8TDj8nvi40pcKFvv2tbRiyYrIPIxefrXmkT\n"
                +"91F3zUKbQL0iW7Aot/0Klj+i4uivqFu359OymJ2C5wJOyZqPPsxUvTdA2EZNX4BseFvJREmvx1CA\n"
                +"gZkANZD4Qzn1b/0WrXfYsbWA4cBeTRR7vjGajBc/oGo2wki0dJksImU8b2dLEf3n3M9dfxiFEAnl\n"
                +"3YKDmT21wamO/hRdWklT+7Ivz6SFnW6HneT42IMNkC4k3d0i0Y2/q7XN5rvMFbH1n6O4NUqHIkzb\n"
                +"CtVljV6+XESmMseyJGKlY6RD7jnhEJq6dGPGSr5h6SAohYljs5Y1e/Dyg243sP75ZO7HfOYPd2Sp\n"
                +"+p5R5szWOuZp5UtLFBhuwlI41LnpuL+4t25LjNHoGhzZCl1rxqcSBGVKLG2sN0XVXfqrt/EykOAV\n"
                +"0WW+S72tRPI73eq0AeRJRRfzcZiequi694eP10Ehh/iiOpQ28yfhsWDvMIxu8o8oK+hpgQvCwecP\n"
                +"7rupdqM9OQYnePb53dd8Tt4hw4WhvSWC/9aNfFXc3jwbHVy5Rw==\n"
                +"</ds:X509Certificate>\n"
                +"</ds:X509Data>\n"
                +"</ds:KeyInfo>\n"
                +"<ds:Object Id=\"xmldsig-42e9e098-2eb8-40ba-88ca-fd4b69af038a-object0\"><root/></ds:Object>\n"
                +"<ds:Object><xades:QualifyingProperties xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\" xmlns:xades141=\"http://uri.etsi.org/01903/v1.4.1#\" Target=\"#xmldsig-42e9e098-2eb8-40ba-88ca-fd4b69af038a\"><xades:SignedProperties Id=\"xmldsig-42e9e098-2eb8-40ba-88ca-fd4b69af038a-signedprops\"><xades:SignedSignatureProperties><xades:SigningTime>2013-10-14T10:59:42.969+02:00</xades:SigningTime><xades:SigningCertificate><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>pC+Isrkdz372kFBisO5sm2jPkPer8nU2DD2+jaTbtU8=</ds:DigestValue></xades:CertDigest><xades:IssuerSerial><ds:X509IssuerName>C=SE,O=SignServer,OU=Testing,CN=DSS Root CA 10</ds:X509IssuerName><ds:X509SerialNumber>378136973006677130</ds:X509SerialNumber></xades:IssuerSerial></xades:Cert><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>hNFFfieDCXZTbEkKVTa0CZBICgwu9yrJZflgpwpVosQ=</ds:DigestValue></xades:CertDigest><xades:IssuerSerial><ds:X509IssuerName>C=SE,O=SignServer,OU=Testing,CN=DSS Root CA 10</ds:X509IssuerName><ds:X509SerialNumber>3624624986813284668</ds:X509SerialNumber></xades:IssuerSerial></xades:Cert></xades:SigningCertificate></xades:SignedSignatureProperties></xades:SignedProperties><xades:UnsignedProperties><xades:UnsignedSignatureProperties><xades:SignatureTimeStamp><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/><xades:EncapsulatedTimeStamp>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</xades:EncapsulatedTimeStamp></xades:SignatureTimeStamp></xades:UnsignedSignatureProperties></xades:UnsignedProperties></xades:QualifyingProperties></ds:Object>\n"
                +"</ds:Signature>";

    /** Hardcoded signed XML document with timestamp response and DOCTYPE. */
    private static final String SIGNED_XML_DOCTYPE = 
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<!DOCTYPE foo [\n"
                + "  <!ELEMENT foo ANY >\n"
                + "]>"
                + "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"xmldsig-42e9e098-2eb8-40ba-88ca-fd4b69af038a\">\n"
                +"<ds:SignedInfo>\n"
                +"<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>\n"
                +"<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n"
                +"<ds:Reference Id=\"xmldsig-42e9e098-2eb8-40ba-88ca-fd4b69af038a-ref0\" Type=\"http://www.w3.org/2000/09/xmldsig#Object\" URI=\"#xmldsig-42e9e098-2eb8-40ba-88ca-fd4b69af038a-object0\">\n"
                +"<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n"
                +"<ds:DigestValue>sRuh+wSYXq5wx5yabOKe5kk69VioHBgksJtR2JG5aMI=</ds:DigestValue>\n"
                +"</ds:Reference>\n"
                +"<ds:Reference Type=\"http://uri.etsi.org/01903#SignedProperties\" URI=\"#xmldsig-42e9e098-2eb8-40ba-88ca-fd4b69af038a-signedprops\">\n"
                +"<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n"
                +"<ds:DigestValue>SMzXP6aRX9dPYCQ2zewLnkHJ8/dmwhzq2enWGldMtPs=</ds:DigestValue>\n"
                +"</ds:Reference>\n"
                +"</ds:SignedInfo>\n"
                +"<ds:SignatureValue Id=\"xmldsig-42e9e098-2eb8-40ba-88ca-fd4b69af038a-sigvalue\">\n"
                +"gizkgI6Fxo87vn+PnEMwBi9P3zbKbiresmI4RtLoEBc0MLk0GYjlkcpB8xxHO4C30N7ue22eUngP\n"
                +"DtU0DelSkCwjl8OUHl9CJ9cjUHgJu1CCk8ZRee7WFwwNNk2DQZHz6QxF5L1SdvlDQQUstqd/tY5K\n"
                +"8YP5Zypn+g+VgsbGbQdR4V//9ZURKQDfsD402CHpSPsSFe8xkkUxQX0Kg/VlO8BqS6+55QRCR8SS\n"
                +"B7GL92x8vLSlfIbdP6XVpIQcoODUEJcURSqF1UurhKlHxxXJlsyznIzCwjJc5Of1rofaZvps+Sby\n"
                +"SFiALjKsgEvmV2B6kvQIQYP6dUg4Q03C483Ipg==\n"
                +"</ds:SignatureValue>\n"
                +"<ds:KeyInfo>\n"
                +"<ds:X509Data>\n"
                +"<ds:X509Certificate>\n"
                +"MIIElTCCAn2gAwIBAgIIBT9pktCBJIowDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJv\n"
                +"b3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYT\n"
                +"AlNFMB4XDTExMDUyNzA5NTAzN1oXDTIxMDUyNzA5NTAzN1owRzERMA8GA1UEAwwIU2lnbmVyIDIx\n"
                +"EDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIIBIjAN\n"
                +"BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAokJJPVkPrn3a55rO6A3Bnbe0nfJR9IDSI8AmFhYE\n"
                +"BLoKfiavx0oMdbdDe+Dkwv78xBkgbj//2lhMCVmss90RzY+d0d0rg2SP8y/DsyxwriqCfuM7lnlg\n"
                +"vSHCYwoX8+uDM7zI53ykKVhqI3ttyFPa8RsjfFOIWqf39++sJUheW4j9x9rutf6qgtjxOYPQwDyg\n"
                +"T9cIVpM7ZehhqVYlcQZRsprMg55s2SN/a78krAW51msoIDgd9+zbsIvzuGqCspO3AN8b2m8tlHTl\n"
                +"A/E4+3OZkSqgpx8FSKIfbKUa866pRzptvcbL/wpFxYkyxqcB6o7CFnWbr3gUPpz8KjuY7ypMmwID\n"
                +"AQABo38wfTAdBgNVHQ4EFgQUSkR/B71idJmR8deZziBAqSzWzhMwDAYDVR0TAQH/BAIwADAfBgNV\n"
                +"HSMEGDAWgBQgeiHe6K27Aqj7cVikCWK52FgFojAOBgNVHQ8BAf8EBAMCBeAwHQYDVR0lBBYwFAYI\n"
                +"KwYBBQUHAwIGCCsGAQUFBwMEMA0GCSqGSIb3DQEBCwUAA4ICAQA+pQuI1QmZLdheCVmc+k1h53uI\n"
                +"v9pBnBKSbKn0/CVznmlPOpJIwwuzcLfCesa6gkG6BabHJwMrU/SpZuWurHxdEKe6fS/ngYnIjFI5\n"
                +"R0Kgl1czqq/tXDjGEpv2x0tZECqLFrkC7a+gjXJPE8TDj8nvi40pcKFvv2tbRiyYrIPIxefrXmkT\n"
                +"91F3zUKbQL0iW7Aot/0Klj+i4uivqFu359OymJ2C5wJOyZqPPsxUvTdA2EZNX4BseFvJREmvx1CA\n"
                +"gZkANZD4Qzn1b/0WrXfYsbWA4cBeTRR7vjGajBc/oGo2wki0dJksImU8b2dLEf3n3M9dfxiFEAnl\n"
                +"3YKDmT21wamO/hRdWklT+7Ivz6SFnW6HneT42IMNkC4k3d0i0Y2/q7XN5rvMFbH1n6O4NUqHIkzb\n"
                +"CtVljV6+XESmMseyJGKlY6RD7jnhEJq6dGPGSr5h6SAohYljs5Y1e/Dyg243sP75ZO7HfOYPd2Sp\n"
                +"+p5R5szWOuZp5UtLFBhuwlI41LnpuL+4t25LjNHoGhzZCl1rxqcSBGVKLG2sN0XVXfqrt/EykOAV\n"
                +"0WW+S72tRPI73eq0AeRJRRfzcZiequi694eP10Ehh/iiOpQ28yfhsWDvMIxu8o8oK+hpgQvCwecP\n"
                +"7rupdqM9OQYnePb53dd8Tt4hw4WhvSWC/9aNfFXc3jwbHVy5Rw==\n"
                +"</ds:X509Certificate>\n"
                +"</ds:X509Data>\n"
                +"</ds:KeyInfo>\n"
                +"<ds:Object Id=\"xmldsig-42e9e098-2eb8-40ba-88ca-fd4b69af038a-object0\"><root/></ds:Object>\n"
                +"<ds:Object><xades:QualifyingProperties xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\" xmlns:xades141=\"http://uri.etsi.org/01903/v1.4.1#\" Target=\"#xmldsig-42e9e098-2eb8-40ba-88ca-fd4b69af038a\"><xades:SignedProperties Id=\"xmldsig-42e9e098-2eb8-40ba-88ca-fd4b69af038a-signedprops\"><xades:SignedSignatureProperties><xades:SigningTime>2013-10-14T10:59:42.969+02:00</xades:SigningTime><xades:SigningCertificate><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>pC+Isrkdz372kFBisO5sm2jPkPer8nU2DD2+jaTbtU8=</ds:DigestValue></xades:CertDigest><xades:IssuerSerial><ds:X509IssuerName>C=SE,O=SignServer,OU=Testing,CN=DSS Root CA 10</ds:X509IssuerName><ds:X509SerialNumber>378136973006677130</ds:X509SerialNumber></xades:IssuerSerial></xades:Cert><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>hNFFfieDCXZTbEkKVTa0CZBICgwu9yrJZflgpwpVosQ=</ds:DigestValue></xades:CertDigest><xades:IssuerSerial><ds:X509IssuerName>C=SE,O=SignServer,OU=Testing,CN=DSS Root CA 10</ds:X509IssuerName><ds:X509SerialNumber>3624624986813284668</ds:X509SerialNumber></xades:IssuerSerial></xades:Cert></xades:SigningCertificate></xades:SignedSignatureProperties></xades:SignedProperties><xades:UnsignedProperties><xades:UnsignedSignatureProperties><xades:SignatureTimeStamp><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/><xades:EncapsulatedTimeStamp>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</xades:EncapsulatedTimeStamp></xades:SignatureTimeStamp></xades:UnsignedSignatureProperties></xades:UnsignedProperties></xades:QualifyingProperties></ds:Object>\n"
                +"</ds:Signature>";
    
    /**
     * Hard-coded signed XML document with a timestamp with a time stamp including a
     * certificate chain with an intermediate sub CA certificate.
     */
    private static final String SIGNED_XML_WITH_INTERMEDIATE_TS_CERT =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"xmldsig-820bd1d9-9110-436f-920c-8f2d02190bbb\">\n"+
            "<ds:SignedInfo>\n"+
            "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>\n"+
            "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n"+
            "<ds:Reference Id=\"xmldsig-820bd1d9-9110-436f-920c-8f2d02190bbb-ref0\" Type=\"http://www.w3.org/2000/09/xmldsig#Object\" URI=\"#xmldsig-820bd1d9-9110-436f-920c-8f2d02190bbb-object0\">\n"+
            "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n"+
            "<ds:DigestValue>z9UB+R4tVWXpuQ6dLRZpBjFvah7FsbTiM2bFY30HctE=</ds:DigestValue>\n"+
            "</ds:Reference>\n"+
            "<ds:Reference Type=\"http://uri.etsi.org/01903#SignedProperties\" URI=\"#xmldsig-820bd1d9-9110-436f-920c-8f2d02190bbb-signedprops\">\n"+
            "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n"+
            "<ds:DigestValue>FfuscicUrhXHaO88IBSnii1mGVQTniNOEiB6lrH5IdE=</ds:DigestValue>\n"+
            "</ds:Reference>\n"+
            "</ds:SignedInfo>\n"+
            "<ds:SignatureValue Id=\"xmldsig-820bd1d9-9110-436f-920c-8f2d02190bbb-sigvalue\">\n"+
            "TF3lv+lVmQq6s7bLJ4nrcuX1APDp5qjir+1MOmD0D74TK6TDEQQ7LyrlMZ/EiwLehd3guMcPUHEC\n"+
            "Z8NtHl+m7ZMDVl/qWtBbfvGXo6tns0BoLhQzjT5rkI7hKdSN2GfpMbSsDGJFIDzHNkiSR4s1+Y14\n"+
            "oA+BFCcPs5RIcM5zDJtJza8SJ23ePoz2ZonmvW5V9ydEyKkCX+2mgwZKjUevOcO51ZADwjxtI6pS\n"+
            "4HiMksqCSi8EYXWhIC8yODcesAPSO3DLNm0RfI8he76MUCreDCmYybT2CTyUmYW7jeujirxxB9p7\n"+
            "yU4sGBychOfuqDmHZosjB2SnRN4t1eFm9YR+yA==\n"+
            "</ds:SignatureValue>\n"+
            "<ds:KeyInfo>\n"+
            "<ds:X509Data>\n"+
            "<ds:X509Certificate>\n"+
            "MIIElTCCAn2gAwIBAgIIBT9pktCBJIowDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJv\n"+
            "b3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYT\n"+
            "AlNFMB4XDTExMDUyNzA5NTAzN1oXDTIxMDUyNzA5NTAzN1owRzERMA8GA1UEAwwIU2lnbmVyIDIx\n"+
            "EDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIIBIjAN\n"+
            "BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAokJJPVkPrn3a55rO6A3Bnbe0nfJR9IDSI8AmFhYE\n"+
            "BLoKfiavx0oMdbdDe+Dkwv78xBkgbj//2lhMCVmss90RzY+d0d0rg2SP8y/DsyxwriqCfuM7lnlg\n"+
            "vSHCYwoX8+uDM7zI53ykKVhqI3ttyFPa8RsjfFOIWqf39++sJUheW4j9x9rutf6qgtjxOYPQwDyg\n"+
            "T9cIVpM7ZehhqVYlcQZRsprMg55s2SN/a78krAW51msoIDgd9+zbsIvzuGqCspO3AN8b2m8tlHTl\n"+
            "A/E4+3OZkSqgpx8FSKIfbKUa866pRzptvcbL/wpFxYkyxqcB6o7CFnWbr3gUPpz8KjuY7ypMmwID\n"+
            "AQABo38wfTAdBgNVHQ4EFgQUSkR/B71idJmR8deZziBAqSzWzhMwDAYDVR0TAQH/BAIwADAfBgNV\n"+
            "HSMEGDAWgBQgeiHe6K27Aqj7cVikCWK52FgFojAOBgNVHQ8BAf8EBAMCBeAwHQYDVR0lBBYwFAYI\n"+
            "KwYBBQUHAwIGCCsGAQUFBwMEMA0GCSqGSIb3DQEBCwUAA4ICAQA+pQuI1QmZLdheCVmc+k1h53uI\n"+
            "v9pBnBKSbKn0/CVznmlPOpJIwwuzcLfCesa6gkG6BabHJwMrU/SpZuWurHxdEKe6fS/ngYnIjFI5\n"+
            "R0Kgl1czqq/tXDjGEpv2x0tZECqLFrkC7a+gjXJPE8TDj8nvi40pcKFvv2tbRiyYrIPIxefrXmkT\n"+
            "91F3zUKbQL0iW7Aot/0Klj+i4uivqFu359OymJ2C5wJOyZqPPsxUvTdA2EZNX4BseFvJREmvx1CA\n"+
            "gZkANZD4Qzn1b/0WrXfYsbWA4cBeTRR7vjGajBc/oGo2wki0dJksImU8b2dLEf3n3M9dfxiFEAnl\n"+
            "3YKDmT21wamO/hRdWklT+7Ivz6SFnW6HneT42IMNkC4k3d0i0Y2/q7XN5rvMFbH1n6O4NUqHIkzb\n"+
            "CtVljV6+XESmMseyJGKlY6RD7jnhEJq6dGPGSr5h6SAohYljs5Y1e/Dyg243sP75ZO7HfOYPd2Sp\n"+
            "+p5R5szWOuZp5UtLFBhuwlI41LnpuL+4t25LjNHoGhzZCl1rxqcSBGVKLG2sN0XVXfqrt/EykOAV\n"+
            "0WW+S72tRPI73eq0AeRJRRfzcZiequi694eP10Ehh/iiOpQ28yfhsWDvMIxu8o8oK+hpgQvCwecP\n"+
            "7rupdqM9OQYnePb53dd8Tt4hw4WhvSWC/9aNfFXc3jwbHVy5Rw==\n"+
            "</ds:X509Certificate>\n"+
            "</ds:X509Data>\n"+
            "</ds:KeyInfo>\n"+
            "<ds:Object Id=\"xmldsig-820bd1d9-9110-436f-920c-8f2d02190bbb-object0\"><root/></ds:Object>\n"+
            "<ds:Object><xades:QualifyingProperties xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\" xmlns:xades141=\"http://uri.etsi.org/01903/v1.4.1#\" Target=\"#xmldsig-820bd1d9-9110-436f-920c-8f2d02190bbb\"><xades:SignedProperties Id=\"xmldsig-820bd1d9-9110-436f-920c-8f2d02190bbb-signedprops\"><xades:SignedSignatureProperties><xades:SigningTime>2013-12-18T14:54:52.176+01:00</xades:SigningTime><xades:SigningCertificate><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>pC+Isrkdz372kFBisO5sm2jPkPer8nU2DD2+jaTbtU8=</ds:DigestValue></xades:CertDigest><xades:IssuerSerial><ds:X509IssuerName>C=SE,O=SignServer,OU=Testing,CN=DSS Root CA 10</ds:X509IssuerName><ds:X509SerialNumber>378136973006677130</ds:X509SerialNumber></xades:IssuerSerial></xades:Cert><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>hNFFfieDCXZTbEkKVTa0CZBICgwu9yrJZflgpwpVosQ=</ds:DigestValue></xades:CertDigest><xades:IssuerSerial><ds:X509IssuerName>C=SE,O=SignServer,OU=Testing,CN=DSS Root CA 10</ds:X509IssuerName><ds:X509SerialNumber>3624624986813284668</ds:X509SerialNumber></xades:IssuerSerial></xades:Cert></xades:SigningCertificate></xades:SignedSignatureProperties></xades:SignedProperties><xades:UnsignedProperties><xades:UnsignedSignatureProperties><xades:SignatureTimeStamp><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/><xades:EncapsulatedTimeStamp>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</xades:EncapsulatedTimeStamp></xades:SignatureTimeStamp></xades:UnsignedSignatureProperties></xades:UnsignedProperties></xades:QualifyingProperties></ds:Object>\n"+
            "</ds:Signature>";
            
            
           
    /**
     *  Hardcoded trust anchor for the form T signed XML
     *  
     *  Contains the following certificates:
     *  
     *  Serial Number: 1913894437955064785 (0x1a8f84d9dfe853d1)
     *  Issuer: CN=DemoRootCA1, OU=EJBCA, O=SignServer Sample, C=SE
     *  Validity
     *      Not Before: Nov  9 14:41:23 2009 GMT
     *      Not After : Nov 10 14:41:23 2034 GMT
     *  Subject: CN=DemoRootCA1, OU=EJBCA, O=SignServer Sample, C=SE
     *
     *  Serial Number: 2738752008854929301 (0x2602007107af7f95)
     *  Issuer: CN=DemoRootCA2, OU=EJBCA, O=SignServer Sample, C=SE
     *  Validity
     *      Not Before: Nov  9 16:09:48 2009 GMT
     *      Not After : Nov 10 16:09:48 2034 GMT
     *  Subject: CN=DemoRootCA2, OU=EJBCA, O=SignServer Sample, C=SE
     *  
     *  Serial Number: 3624624986813284668 (0x324d4138af02c13c)
     *  Issuer: CN=DSS Root CA 10, OU=Testing, O=SignServer, C=SE
     *  Validity
     *      Not Before: May 27 08:14:27 2011 GMT
     *      Not After : May 27 08:14:27 2036 GMT
     *  Subject: CN=DSS Root CA 10, OU=Testing, O=SignServer, C=SE
     */
    private static String TRUSTANCHORS_FORM_T = "\n-----BEGIN CERTIFICATE-----\nMIICfjCCAeegAwIBAgIIGo+E2d/oU9EwDQYJKoZIhvcNAQEFBQAwTzEUMBIGA1UEAwwLRGVtb1Jvb3RDQTExDjAMBgNVBAsMBUVKQkNBMRowGAYDVQQKDBFTaWduU2VydmVyIFNhbXBsZTELMAkGA1UEBhMCU0UwHhcNMDkxMTA5MTQ0MTIzWhcNMzQxMTEwMTQ0MTIzWjBPMRQwEgYDVQQDDAtEZW1vUm9vdENBMTEOMAwGA1UECwwFRUpCQ0ExGjAYBgNVBAoMEVNpZ25TZXJ2ZXIgU2FtcGxlMQswCQYDVQQGEwJTRTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAm9kfNe5zQ6d/J4FShC0ud2KAX7Wso+ulcI/2zyYFUnj2QcUVZ3KEwXyDjWlFOkXX5LVbmiDMglr/iPgKeh+L1Pd4nQ3ydW+jG1a0Yxe6eyaQqaflrsIai3JXmllUMp7kTc7ylcuuNmkxiTX2vhYltqgdVdfJ29eDwBVnkmPAsNsCAwEAAaNjMGEwHQYDVR0OBBYEFIC1Yu2E2Ia344+IumPUHchd5ylLMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUgLVi7YTYhrfjj4i6Y9QdyF3nKUswDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBBQUAA4GBAI+eyurSlvV/W23UskU85CsPid/Hiy0cvMWtc5i+ZWQTDEyW53n1nc2yHpSBY30wUbd8p0Qbdl03Y+S/n+arItiAPqC/RZttgTfcztwSU/nWugIrgwoPltA4H582IBzO7cmJ26jGwQQsD6uCCTQSJK9xlqXQw8Uyj+N6SvE3p+wq\n-----END CERTIFICATE-----\n"
            +"\n-----BEGIN CERTIFICATE-----\nMIIDPTCCAvygAwIBAgIIJgIAcQevf5UwCQYHKoZIzjgEAzBPMRQwEgYDVQQDDAtEZW1vUm9vdENBMjEOMAwGA1UECwwFRUpCQ0ExGjAYBgNVBAoMEVNpZ25TZXJ2ZXIgU2FtcGxlMQswCQYDVQQGEwJTRTAeFw0wOTExMDkxNjA5NDhaFw0zNDExMTAxNjA5NDhaME8xFDASBgNVBAMMC0RlbW9Sb290Q0EyMQ4wDAYDVQQLDAVFSkJDQTEaMBgGA1UECgwRU2lnblNlcnZlciBTYW1wbGUxCzAJBgNVBAYTAlNFMIIBtzCCASsGByqGSM44BAEwggEeAoGBAI+d9uiMBBzqdvlV3wSMdwRv/Qx2POGqh+m0M0tMYEwIGBdZHm3+QSKIDTjcLRJgCGgTXSAJPCZtp43+kWCV5iGbbemBchOCh4Oe/4IPQERlfJhyMH0gXLglG9KSbuKkqMSzaZoZk06q750KBKusKhK+mvhp08++KyXZna3p6itdAhUAntjYRJsYqqQtIt0htCGCEAHCkg8CgYA4E4VMplm16uizoUL+9erNtLI886f8pdO5vXhcQG9IpZ0J7N6M4WQy8CFzTKjRJLs27TO2gDP8BE50mMOnbRvYmGIJsQ9lZHTjUqltWh9PJ0VKF0fCwQbA3aY+v8PiHxELvami+YyBiYjE2C6b1ArKOw1QsEL0KakJcr22yWFaKgOBhQACgYEAiTsSMcEKhYCWg2ULDwD/4ueYyDcRvyoSrT7uCdGU0Y/w2wPuI+kV5RfHxjs6YLDuJsQJg6rfi3RfgmwQJVzClDfgUN12qzRbSidepg/7ipkCGk0/eyY1A99z3K+FUZm2MVgune4ywCorPUpxz6WHS7/dSWYMWtSrr92PzgnwZbKjYzBhMB0GA1UdDgQWBBRJ3xUuyl6ZroD3lFm3nw/AhCPeJTAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFEnfFS7KXpmugPeUWbefD8CEI94lMA4GA1UdDwEB/wQEAwIBhjAJBgcqhkjOOAQDAzAAMC0CFQCEGSmvJf6rxy6u7ZqY25qE7Hy21gIUPW4q++YIS2fHyu+H4Pjgnodx5zI=\n-----END CERTIFICATE-----\n"
            +"\n-----BEGIN CERTIFICATE-----\n"
            +"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"
            +"dMwk/ZXzsDjMZEtENaBXzAefYA==\n"
            +"-----END CERTIFICATE-----";

    /**
     *  Hardcoded trust anchor missing certs for the embedded time stamp
     * 
     *  Contains the following certificates:
     * 
     *  Serial Number: 1913894437955064785 (0x1a8f84d9dfe853d1)
     *  Issuer: CN=DemoRootCA1, OU=EJBCA, O=SignServer Sample, C=SE
     *  Validity
     *      Not Before: Nov  9 14:41:23 2009 GMT
     *      Not After : Nov 10 14:41:23 2034 GMT
     *  Subject: CN=DemoRootCA1, OU=EJBCA, O=SignServer Sample, C=SE
     *
     *  Serial Number: 2738752008854929301 (0x2602007107af7f95)
     *  Issuer: CN=DemoRootCA2, OU=EJBCA, O=SignServer Sample, C=SE
     *  Validity
     *      Not Before: Nov  9 16:09:48 2009 GMT
     *      Not After : Nov 10 16:09:48 2034 GMT
     *  Subject: CN=DemoRootCA2, OU=EJBCA, O=SignServer Sample, C=SE
     * 
     */
    private static String TRUSTANCHORS_MISSING_TS = "\n-----BEGIN CERTIFICATE-----\nMIICfjCCAeegAwIBAgIIGo+E2d/oU9EwDQYJKoZIhvcNAQEFBQAwTzEUMBIGA1UEAwwLRGVtb1Jvb3RDQTExDjAMBgNVBAsMBUVKQkNBMRowGAYDVQQKDBFTaWduU2VydmVyIFNhbXBsZTELMAkGA1UEBhMCU0UwHhcNMDkxMTA5MTQ0MTIzWhcNMzQxMTEwMTQ0MTIzWjBPMRQwEgYDVQQDDAtEZW1vUm9vdENBMTEOMAwGA1UECwwFRUpCQ0ExGjAYBgNVBAoMEVNpZ25TZXJ2ZXIgU2FtcGxlMQswCQYDVQQGEwJTRTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAm9kfNe5zQ6d/J4FShC0ud2KAX7Wso+ulcI/2zyYFUnj2QcUVZ3KEwXyDjWlFOkXX5LVbmiDMglr/iPgKeh+L1Pd4nQ3ydW+jG1a0Yxe6eyaQqaflrsIai3JXmllUMp7kTc7ylcuuNmkxiTX2vhYltqgdVdfJ29eDwBVnkmPAsNsCAwEAAaNjMGEwHQYDVR0OBBYEFIC1Yu2E2Ia344+IumPUHchd5ylLMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUgLVi7YTYhrfjj4i6Y9QdyF3nKUswDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBBQUAA4GBAI+eyurSlvV/W23UskU85CsPid/Hiy0cvMWtc5i+ZWQTDEyW53n1nc2yHpSBY30wUbd8p0Qbdl03Y+S/n+arItiAPqC/RZttgTfcztwSU/nWugIrgwoPltA4H582IBzO7cmJ26jGwQQsD6uCCTQSJK9xlqXQw8Uyj+N6SvE3p+wq\n-----END CERTIFICATE-----\n";
    
    /**
     * Sub CA certificate for TSA using intermediate certificate.
     * 
     * subject=/CN=DSS Sub CA 11/OU=Testing/O=SignServer/C=SE
     * issuer=/CN=DSS Root CA 10/OU=Testing/O=SignServer/C=SE
     * 
     */
    private final static String SUB_CA_CERT =
            "-----BEGIN CERTIFICATE-----\n"+
            "MIIEfjCCAmagAwIBAgIINRnImL/vDX4wDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJv\n"+
            "b3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYT\n"+
            "AlNFMB4XDTExMTEwMzIxMzUwOVoXDTM2MDUyNzA4MTQyN1owTDEWMBQGA1UEAwwNRFNTIFN1YiBD\n"+
            "QSAxMTEQMA4GA1UECwwHVGVzdGluZzETMBEGA1UECgwKU2lnblNlcnZlcjELMAkGA1UEBhMCU0Uw\n"+
            "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCg4ovlcxaRM8g3RJrOUrSCH7bJhWnNN54E\n"+
            "Z3a4aIAGBYjN7B8+CtnFDNaaC57mCLI5U64vRzYRTbphA5X5XiHsz+eEaHFkwKS+EovvjOWUPzYu\n"+
            "ReRpyRaDyxEUYfmVqSa3fFa6Vn7vsE8N9mfwyNMT/q56SLuNO7Un2EAgvoTdaMen6UbISg4ONNI7\n"+
            "XmhtaDQvBe5+px0NIBCFw5qnvAMUz4nRJcKRZ6QKvRFJPux9R048WSrBfAxkKBPzIiKtkAfeOs3E\n"+
            "2anPIDwiaPdWD4AjraFjSfTOVxzNrp0D/+1s3zVvQDBGQoAw8QAUnb3bZS8siY0Oo943j4McSBFI\n"+
            "3VHNAgMBAAGjYzBhMB0GA1UdDgQWBBQcYEFK3pit5dYDiuhmgql+sPIChzAPBgNVHRMBAf8EBTAD\n"+
            "AQH/MB8GA1UdIwQYMBaAFCB6Id7orbsCqPtxWKQJYrnYWAWiMA4GA1UdDwEB/wQEAwIBhjANBgkq\n"+
            "hkiG9w0BAQsFAAOCAgEAMW0jL9WGrV6Hn5ZaNmAu2XPOF25vuiVFCgfmKInFPROkvxIOPBOgAumX\n"+
            "43jcL1ATWV6zoRscPxflp5E1C55W5xaxVd4YMuxjZhxZj3qOHbkCjJd5V47nFEiqazgdnFdFE0AP\n"+
            "pe5/gWhjY5fYc2erS+RnojM//qzeeivd7QD2SC9FJ79cBsclzUgtZ2hdtwaKFFKzxYDkMelJa+SZ\n"+
            "MBEw1FgF8abynbkga8hFHVvnIsUxrIEGIPxHXC/gvpMpOLu/hAg+p+negdQKnM6HNpl+TmJdaz37\n"+
            "fe49mzylS9GwSj+iVPvHy2H9eEL9MuXRGpTRJbzBKLlq3q3Rx5udtZfalN6EcKCr7yTKumF5SjcM\n"+
            "PoF1LLYKO70FZ4dSSi3lyMlTThqb0pr4XF0zq/4j8KHiYboomxrG+LVhbqT0x51D1UebOPd8S5VK\n"+
            "2l0NEC6xQDqDvuWjveI/wwYXDIWXj/6UzQGvVZ+vKb6DXFUJ9oPw4LD+vFppv90XeIzwzm7EMV3G\n"+
            "rzEvfW5rLmCVGgTggPHowPWdNgtFE/n29uxO58V73Com1cFnfryfwGp1efkMxj9yBjZwAgYUDCte\n"+
            "LbKLgL6GH//J5r9nAQ8r3z76mtdtE0aU1swza03wVsJySOdCNFI9iZAJLe7SZ4k7YCqevF5p2S8E\n"+
            "u/5niX2igtu5iNzcReA=\n"+
            "-----END CERTIFICATE-----\n";
    
    /**
     * Setting up key-pairs, mocked crypto tokens, certificates and CRLs used
     * by the tests.
     * 
     * @throws java.lang.Exception
     */
    @BeforeClass
    public static void setUpClass() throws Exception {       
        Security.addProvider(new BouncyCastleProvider());
        JcaX509CertificateConverter conv = new JcaX509CertificateConverter();
        
        // Root CA, sub CA
        rootcaCRLFile = File.createTempFile("xadestest-", "-rootca.crl");
        LOG.debug("rootcaCRLFile: " + rootcaCRLFile);
        subca1CRLFile = File.createTempFile("xadestest-", "-subca.crl");
        LOG.debug("subcaCRLFile: " + subca1CRLFile);
        rootcaKeyPair = CryptoUtils.generateRSA(1024);
        anotherKeyPair = CryptoUtils.generateRSA(1024);
        rootcaCert = new CertBuilder()
                .setSelfSignKeyPair(rootcaKeyPair)
                .setSubject("CN=Root, O=XAdES Test, C=SE")
                .addExtension(new CertExt(Extension.keyUsage, false, new X509KeyUsage(X509KeyUsage.keyCertSign | X509KeyUsage.cRLSign | X509KeyUsage.digitalSignature)))
                .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(true)))
                .build();
        final KeyPair subca1KeyPair = CryptoUtils.generateRSA(1024);
        subca1Cert = new CertBuilder()
                .setIssuerPrivateKey(rootcaKeyPair.getPrivate())
                .setIssuer(rootcaCert.getSubject())
                .setSubjectPublicKey(subca1KeyPair.getPublic())
                .addCDPURI(rootcaCRLFile.toURI().toURL().toExternalForm())
                .setSubject("CN=Sub 1, O=XAdES Test, C=SE")
                .addExtension(new CertExt(Extension.keyUsage, false, new X509KeyUsage(X509KeyUsage.keyCertSign | X509KeyUsage.cRLSign)))
                .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(true)))
                .build();
        subca2KeyPair = CryptoUtils.generateRSA(1024);
        subca2Cert = new CertBuilder()
                .setIssuerPrivateKey(rootcaKeyPair.getPrivate())
                .setIssuer(rootcaCert.getSubject())
                .setSubjectPublicKey(subca2KeyPair.getPublic())
                .setSubject("CN=Sub 2, O=XAdES Test, C=SE")
                .addExtension(new CertExt(Extension.keyUsage, false, new X509KeyUsage(X509KeyUsage.keyCertSign | X509KeyUsage.cRLSign | X509KeyUsage.digitalSignature)))
                .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(true)))
                .addExtension(new CertExt(Extension.authorityInfoAccess, false,
                        new AuthorityInformationAccess(AccessDescription.id_ad_ocsp, 
                                new GeneralName(GeneralName.uniformResourceIdentifier, "http://ocsp.example.com"))))
                .build();
        
        // Signer 1 is issued directly by the root CA
        final KeyPair signer1KeyPair = CryptoUtils.generateRSA(1024);
        final X509CertificateHolder signer1Cert = new CertBuilder()
                .setIssuerPrivateKey(rootcaKeyPair.getPrivate())
                .setIssuer(rootcaCert.getSubject())
                .setSubjectPublicKey(signer1KeyPair.getPublic())
                .setSubject("CN=Signer 1, O=XAdES Test, C=SE")
                .addCDPURI(rootcaCRLFile.toURI().toURL().toExternalForm())
                .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(false)))
                .build();
        final List<Certificate> chain1 = Arrays.<Certificate>asList(
                    conv.getCertificate(signer1Cert),
                    conv.getCertificate(rootcaCert)
                );
        token1 = new MockedCryptoToken(
                signer1KeyPair.getPrivate(),
                signer1KeyPair.getPublic(), 
                conv.getCertificate(signer1Cert), 
                chain1, 
                "BC");
        LOG.debug("Chain 1: \n" + new String(CertTools.getPemFromCertificateChain(chain1), "ASCII") + "\n");
        
        // Sign a document by signer 1
        XAdESSigner instance = new MockedXAdESSigner(token1);
        WorkerConfig config = new WorkerConfig();
        instance.init(4712, config, new SignServerContext(), null);
        RequestContext requestContext = new RequestContext();
        requestContext.setServices(new ServicesImpl());
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-201-1");
        signedXml1 = signXML(instance, "<test201/>", requestContext);
        LOG.debug("Signed document by signer 1:\n\n" + signedXml1 + "\n");
        
        
        
        // Signer 2 is issued by the sub CA
        final KeyPair signer2KeyPair = CryptoUtils.generateRSA(1024);
        final X509CertificateHolder signer2Cert = new CertBuilder()
                .setIssuerPrivateKey(subca1KeyPair.getPrivate())
                .setIssuer(subca1Cert.getSubject())
                .setSubjectPublicKey(signer2KeyPair.getPublic())
                .setSubject("CN=Signer 2, O=XAdES Test, C=SE")
                .addCDPURI(subca1CRLFile.toURI().toURL().toExternalForm())
                .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(false)))
                .build();
        final List<Certificate> chain2 = Arrays.<Certificate>asList(
                    conv.getCertificate(signer2Cert),
                    conv.getCertificate(subca1Cert),
                    conv.getCertificate(rootcaCert)
                );
        token2 = new MockedCryptoToken(
                signer2KeyPair.getPrivate(),
                signer2KeyPair.getPublic(), 
                conv.getCertificate(signer2Cert), 
                chain2, 
                "BC");
        LOG.debug("Chain 2: \n" + new String(CertTools.getPemFromCertificateChain(chain2)) + "\n");
        
        // Sign a document by signer 2
        instance = new MockedXAdESSigner(token2);
        config = new WorkerConfig();
        instance.init(4713, config, null, null);
        requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-202-1");
        signedXml2 = signXML(instance, "<test202/>", requestContext);
        LOG.debug("Signed document by signer 2:\n\n" + signedXml2 + "\n");
        
        // CRL with all active (empty CRL)
        rootcaCRLEmpty = new CRLBuilder()
                .setIssuerPrivateKey(rootcaKeyPair.getPrivate())
                .setIssuer(rootcaCert.getSubject())
                .build();
        subca1CRLEmpty = new CRLBuilder()
                .setIssuerPrivateKey(subca1KeyPair.getPrivate())
                .setIssuer(subca1Cert.getSubject())
                .build();
        rootcaCRLSubCAAndSigner1Revoked = new CRLBuilder()
                .setIssuerPrivateKey(rootcaKeyPair.getPrivate())
                .setIssuer(rootcaCert.getSubject())
                .addCRLEntry(subca1Cert.getSerialNumber(), new Date(), CRLReason.keyCompromise)
                .addCRLEntry(signer1Cert.getSerialNumber(), new Date(), CRLReason.keyCompromise)
                .build();
        subca1CRLSigner2Revoked = new CRLBuilder()
                .setIssuerPrivateKey(subca1KeyPair.getPrivate())
                .setIssuer(subca1Cert.getSubject())
                .addCRLEntry(signer2Cert.getSerialNumber(), new Date(), CRLReason.keyCompromise)
                .build();
        otherCRL = new CRLBuilder()
                .setIssuer(subca1Cert.getSubject()) // Setting Sub CA DN all though an other key will be used
                .build();
        
        // signer 3, issued by the root CA with an OCSP authority information access in the signer cert
        final KeyPair signer3KeyPair = CryptoUtils.generateRSA(1024);
        signer3Cert = new CertBuilder()
                .setIssuerPrivateKey(rootcaKeyPair.getPrivate())
                .setIssuer(rootcaCert.getSubject())
                .setSubjectPublicKey(signer3KeyPair.getPublic())
                .setSubject("CN=Signer 3, O=XAdES Test, C=SE")
                .addExtension(new CertExt(Extension.authorityInfoAccess, false,
                        new AuthorityInformationAccess(AccessDescription.id_ad_ocsp, 
                                new GeneralName(GeneralName.uniformResourceIdentifier, "http://ocsp.example.com"))))
                .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(false)))
                .build();
        final List<Certificate> chain3 = Arrays.<Certificate>asList(
                    conv.getCertificate(signer3Cert),
                    conv.getCertificate(rootcaCert)
                );
        token3 = new MockedCryptoToken(
                signer3KeyPair.getPrivate(),
                signer3KeyPair.getPublic(), 
                conv.getCertificate(signer3Cert), 
                chain3, 
                "BC");
        LOG.debug("Chain 3: \n" + new String(CertTools.getPemFromCertificateChain(chain3)) + "\n");
        
        // signer 4, issued by the sub CA2 with an OCSP authority information access in the signer cert
        final KeyPair signer4KeyPair = CryptoUtils.generateRSA(1024);
        signer4Cert = new CertBuilder()
                .setIssuerPrivateKey(subca2KeyPair.getPrivate())
                .setIssuer(subca2Cert.getSubject())
                .setSubjectPublicKey(signer4KeyPair.getPublic())
                .setSubject("CN=Signer 4, O=XAdES Test, C=SE")
                .addExtension(new CertExt(Extension.authorityInfoAccess, false,
                        new AuthorityInformationAccess(AccessDescription.id_ad_ocsp, 
                                new GeneralName(GeneralName.uniformResourceIdentifier, "http://ocsp.example.com"))))
                .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(false)))
                .build();
        final List<Certificate> chain4 = Arrays.<Certificate>asList(
                    conv.getCertificate(signer4Cert),
                    conv.getCertificate(subca2Cert),
                    conv.getCertificate(rootcaCert)
                );
        token4 = new MockedCryptoToken(
                signer4KeyPair.getPrivate(),
                signer4KeyPair.getPublic(), 
                conv.getCertificate(signer4Cert), 
                chain4, 
                "BC");
        LOG.debug("Chain 4: \n" + new String(CertTools.getPemFromCertificateChain(chain4)) + "\n");
        
        // ocspSigner 1, OCSP responder issued by the root CA with an ocsp-nocheck in the signer cert
        ocspSigner1KeyPair = CryptoUtils.generateRSA(1024);
        ocspSigner1Cert = new CertBuilder()
                .setIssuerPrivateKey(rootcaKeyPair.getPrivate())
                .setIssuer(rootcaCert.getSubject())
                .setSubjectPublicKey(ocspSigner1KeyPair.getPublic())
                .setSubject("CN=OCSP Responder 1, O=XAdES Test, C=SE")
                .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(false)))
                .addExtension(new CertExt(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning)))
                .addExtension(new CertExt(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck, false, DERNull.INSTANCE))
                .build();
        
        // ocspSigner 2, OCSP responder issued by the sub CA2 with an ocsp-nocheck in the signer cert
        ocspSigner2KeyPair = CryptoUtils.generateRSA(1024);
        ocspSigner2Cert = new CertBuilder()
                .setIssuerPrivateKey(subca2KeyPair.getPrivate())
                .setIssuer(subca2Cert.getSubject())
                .setSubjectPublicKey(ocspSigner2KeyPair.getPublic())
                .setSubject("CN=OCSP Responder 2, O=XAdES Test, C=SE")
                .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(false)))
                .addExtension(new CertExt(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning)))
                .addExtension(new CertExt(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck, false, DERNull.INSTANCE))
                .build();
        
        // Sign a document by signer 3
        instance = new MockedXAdESSigner(token3);
        config = new WorkerConfig();
        instance.init(4714, config, null, null);
        requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-203-1");
        signedXml3 = signXML(instance, "<test203/>", requestContext);
        LOG.debug("Signed document by signer 3:\n\n" + signedXml3 + "\n"); 
        
        // Sign a document by signer 4
        instance = new MockedXAdESSigner(token4);
        config = new WorkerConfig();
        instance.init(4715, config, null, null);
        requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-204-1");
        signedXml4 = signXML(instance, "<test204/>", requestContext);
        LOG.debug("Signed document by signer 4:\n\n" + signedXml4 + "\n"); 
        
        // Signer 5 is issued directly by the root CA
        final KeyPair signer5KeyPair = CryptoUtils.generateRSA(1024);
        signer5Cert = new CertBuilder()
                .setIssuerPrivateKey(rootcaKeyPair.getPrivate())
                .setIssuer(rootcaCert.getSubject())
                .setSubjectPublicKey(signer5KeyPair.getPublic())
                .setSubject("CN=Signer 5, O=XAdES Test, C=SE")
                .addCDPURI(rootcaCRLFile.toURI().toURL().toExternalForm())
                .addExtension(new CertExt(Extension.authorityInfoAccess, false,
                        new AuthorityInformationAccess(AccessDescription.id_ad_ocsp, 
                                new GeneralName(GeneralName.uniformResourceIdentifier, "http://ocsp.example.com"))))
                .addExtension(new CertExt(Extension.basicConstraints, false, new BasicConstraints(false)))
                .build();
        final List<Certificate> chain5 = Arrays.<Certificate>asList(
                    conv.getCertificate(signer5Cert),
                    conv.getCertificate(rootcaCert)
                );
        token5 = new MockedCryptoToken(
                signer5KeyPair.getPrivate(),
                signer5KeyPair.getPublic(), 
                conv.getCertificate(signer1Cert), 
                chain5, 
                "BC");
        LOG.debug("Chain 5: \n" + new String(CertTools.getPemFromCertificateChain(chain5)) + "\n");
        
        // Sign a document by signer 5
        instance = new MockedXAdESSigner(token5);
        config = new WorkerConfig();
        instance.init(4712, config, null, null);
        requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-205-1");
        signedXml5 = signXML(instance, "<test205/>", requestContext);
        LOG.debug("Signed document by signer 5:\n\n" + signedXml5 + "\n");
        
        // CRL with signer 5 revoked
        rootcaCRLSigner5Revoked = new CRLBuilder()
                .setIssuerPrivateKey(rootcaKeyPair.getPrivate())
                .setIssuer(rootcaCert.getSubject())
                .addCRLEntry(signer5Cert.getSerialNumber(), new Date(), CRLReason.keyCompromise)
                .build();
    }
    
    private static String signXML(XAdESSigner instance, String xml, RequestContext requestContext) throws Exception {
        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(xml.getBytes(StandardCharsets.UTF_8));
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false);
                ) {
            SignatureRequest request = new SignatureRequest(201, requestData, responseData);
            instance.processData(request, requestContext);
            byte[] data = responseData.toReadableData().getAsByteArray();
            return new String(data, StandardCharsets.UTF_8);
        }
    }

    @Before
    public void beforeTest() throws Exception {
        updateCRLs(rootcaCRLEmpty, subca1CRLEmpty);
    }
    
    /**
     * Test validation of document signed by signer1 without revocation checking.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testSigner1_noRevocationChecking() throws Exception {
        LOG.info("signer1");

        XAdESValidator instance = new XAdESValidator();
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
        config.setProperty("REVOCATION_CHECKING", "false");
        
        updateCRLs(rootcaCRLEmpty, subca1CRLEmpty);
        
        instance.init(4714, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-300-0");
        DocumentValidationResponse response = validateXML(instance, 300, signedXml1, requestContext);
        
        assertTrue("valid document", response.isValid());
        assertNotNull("returned signer cert", response.getCertificateValidationResponse().getValidation().getCertificate());
        assertEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidationResponse().getValidation().getStatus());
    }
    
    /**
     * Test validation of document signed by signer1 with CRL where no
     * cert is revoked.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testSigner1_crlNoRevoked() throws Exception {
        LOG.info("signer1");

        XAdESValidator instance = new XAdESValidator();
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
        config.setProperty("REVOCATION_CHECKING", "true");
        
        updateCRLs(rootcaCRLEmpty, subca1CRLEmpty);
        
        instance.init(4714, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-301-1");
        DocumentValidationResponse response = validateXML(instance, 301, signedXml1, requestContext);
        
        assertTrue("valid document", response.isValid());
        assertNotNull("returned signer cert", response.getCertificateValidationResponse().getValidation().getCertificate());
        assertEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidationResponse().getValidation().getStatus());
    }
    
    /**
     * Test validation of document signed by signer1 with CRL where the signer
     * certificate is revoked.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testSigner1_crlSignerRevoked() throws Exception {
        LOG.info("testSigner1_crlSignerRevoked");

        XAdESValidator instance = new XAdESValidator();
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
        config.setProperty("REVOCATION_CHECKING", "true");
        
        updateCRLs(rootcaCRLSubCAAndSigner1Revoked, subca1CRLEmpty);
        
        instance.init(4714, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-302-1");
        DocumentValidationResponse response = validateXML(instance, 302, signedXml1, requestContext);
        
        assertFalse("valid document", response.isValid());
        assertNotEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidationResponse().getValidation().getStatus());
    }
    
    /**
     * Test validation of document signed by signer2 without revocation checking.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testSigner2_noRevocationChecking() throws Exception {
        LOG.info("signer2");

        XAdESValidator instance = new XAdESValidator();
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
        
        // We need to configure intermediate certificate as XAdES4j does not seem to include intermediate certificates in the signed document
        config.setProperty("CERTIFICATES", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(subca1Cert)))));
        
        config.setProperty("REVOCATION_CHECKING", "false");
        
        updateCRLs(rootcaCRLEmpty, subca1CRLEmpty);
        
        instance.init(4714, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-303-1");
        DocumentValidationResponse response = validateXML(instance, 303, signedXml2, requestContext);
        
        assertTrue("valid document", response.isValid());
        assertNotNull("returned signer cert", response.getCertificateValidationResponse().getValidation().getCertificate());
        assertEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidationResponse().getValidation().getStatus());
    }
    
    /**
     * Test validation of document signed by signer2 with CRL where no
     * cert is revoked.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testSigner2_crlNoRevoked() throws Exception {
        LOG.info("testSigner2_crlNoRevoked");

        XAdESValidator instance = new XAdESValidator();
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
        config.setProperty("REVOCATION_CHECKING", "true");
        
        // We need to configure intermediate certificate as XAdES4j does not seem to include intermediate certificates in the signed document
        config.setProperty("CERTIFICATES", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(subca1Cert)))));
        
        updateCRLs(rootcaCRLEmpty, subca1CRLEmpty);
        
        instance.init(4714, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-304-1");
        DocumentValidationResponse response = validateXML(instance, 304, signedXml2, requestContext);
        
        assertTrue("valid document", response.isValid());
        assertNotNull("returned signer cert", response.getCertificateValidationResponse().getValidation().getCertificate());
        assertEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidationResponse().getValidation().getStatus());
    }
    
    /**
     * Test validation of document signed by signer2 with CRL where the signer
     * certificate is revoked.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testSigner2_crlSignerRevoked() throws Exception {
        LOG.info("testSigner2_crlSignerRevoked");

        XAdESValidator instance = new XAdESValidator();
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
        config.setProperty("REVOCATION_CHECKING", "true");
        
        // We need to configure intermediate certificate as XAdES4j does not seem to include intermediate certificates in the signed document
        config.setProperty("CERTIFICATES", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(subca1Cert)))));
        
        updateCRLs(rootcaCRLEmpty, subca1CRLSigner2Revoked);
        
        instance.init(4714, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-305-1");
        DocumentValidationResponse response = validateXML(instance, 305, signedXml2, requestContext);
        
        assertFalse("valid document", response.isValid());
        assertNotEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidationResponse().getValidation().getStatus());
    }
    
    /**
     * Test validation of document signed by signer2 with CRL where the sub CA
     * certificate is revoked.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testSigner2_crlCARevoked() throws Exception {
        LOG.info("testSigner2_crlCARevoked");

        XAdESValidator instance = new XAdESValidator();
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
        config.setProperty("REVOCATION_CHECKING", "true");
        
        // We need to configure intermediate certificate as XAdES4j does not seem to include intermediate certificates in the signed document
        config.setProperty("CERTIFICATES", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(subca1Cert)))));
        
        updateCRLs(rootcaCRLSubCAAndSigner1Revoked, subca1CRLEmpty);
        
        instance.init(4714, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-305-1");
        DocumentValidationResponse response = validateXML(instance, 305, signedXml2, requestContext);
        
        assertFalse("valid document", response.isValid());
        assertNotEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidationResponse().getValidation().getStatus());
    }
    
    /**
     * Test validation of document signed by signer2 where the sub CA CRL is
     * signed by an other CA and thus not trusted.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testSigner2_badCRL() throws Exception {
        LOG.info("testSigner2_badCRL");

        XAdESValidator instance = new XAdESValidator();
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
        config.setProperty("REVOCATION_CHECKING", "true");
        
        // We need to configure intermediate certificate as XAdES4j does not seem to include intermediate certificates in the signed document
        config.setProperty("CERTIFICATES", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(subca1Cert)))));
        
        updateCRLs(rootcaCRLEmpty, otherCRL);
        
        instance.init(4714, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-306-1");
        DocumentValidationResponse response = validateXML(instance, 306, signedXml2, requestContext);
        
        assertFalse("valid document", response.isValid());
        assertNotEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidationResponse().getValidation().getStatus());
    }

    private static OCSPResponse convert(org.signserver.test.utils.builders.ocsp.OCSPResponse response) {
        OCSPResponse result = new OCSPResponse();
        result.setError(OCSPResponse.Error.valueOf(response.getError().name()));
        result.setFailedResponses(response.getFailedResponses());
        result.setHttpReturnCode(response.getHttpReturnCode());
        result.setIssuerDN(response.getIssuerDN());
        result.setResp(response.getResp());
        result.setResponseObject(response.getResponseObject());
        result.setResponseTime(response.getResponseTime());
        result.setResponsesFromOther(response.getResponsesFromOther());
        result.setSignerCertificate(response.getSignerCertificate());
        return result;
    }
    
    /**
     * Positive test for signer 3 were an OCSP response is signed by the CA
     * and returns the status GOOD for the signer 3 certificate.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testSigner3_withOnlyOCSP_ca_ok() throws Exception {
        LOG.info("testSigner3_withOnlyOCSP_ca_ok");

        final ArrayList<OCSPReq> requests = new ArrayList<>();
        XAdESValidator instance = new XAdESValidator() {
            @Override
            protected OCSPResponse doQueryOCSPResponder(URL url, OCSPReq request) throws IOException, OCSPException {
                try {
                    requests.add(request);
                    
                    // Create response signed by the CA
                    return convert(new OCSPResponseBuilder()
                            .addResponse(new OcspRespObject(new CertificateID(new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)), rootcaCert, signer3Cert.getSerialNumber()), CertificateStatus.GOOD))
                            .setResponseSignerCertificate(new JcaX509CertificateConverter().getCertificate(rootcaCert))
                            .setIssuerPrivateKey(rootcaKeyPair.getPrivate())
                            .setChain(new X509CertificateHolder[] {rootcaCert}).build());
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            }
        };
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
        config.setProperty("REVOCATION_CHECKING", "true");
       
        instance.init(4715, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-307-1");
        DocumentValidationResponse response = validateXML(instance, 307, signedXml3, requestContext);
        
        assertEquals("OCSP calls", 1, requests.size());
        
        assertTrue("valid document", response.isValid());
        assertEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidationResponse().getValidation().getStatus());
    }
    
    /**
     * Positive test for signer 3 were an OCSP response is signed by external
     * responder and returns the status GOOD for the signer 3 certificate.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testSigner3_withOnlyOCSP_responder_ok() throws Exception {
        LOG.info("testSigner3_withOnlyOCSP_responder_ok");

        final ArrayList<OCSPReq> requests = new ArrayList<>();
        XAdESValidator instance = new XAdESValidator() {
            @Override
            protected OCSPResponse doQueryOCSPResponder(URL url, OCSPReq request) throws IOException, OCSPException {
                try {
                    requests.add(request);
                    
                    // Create response signed by the CA
                    return convert(new OCSPResponseBuilder()
                            .addResponse(new OcspRespObject(new CertificateID(new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)), rootcaCert, signer3Cert.getSerialNumber()), CertificateStatus.GOOD))
                            .setResponseSignerCertificate(new JcaX509CertificateConverter().getCertificate(ocspSigner1Cert))
                            .setIssuerPrivateKey(ocspSigner1KeyPair.getPrivate())
                            .setChain(new X509CertificateHolder[] {ocspSigner1Cert}).build());
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            }
        };
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
        config.setProperty("REVOCATION_CHECKING", "true");
       
        instance.init(4715, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-307-1");
        DocumentValidationResponse response = validateXML(instance, 307, signedXml3, requestContext);
        
        assertEquals("OCSP calls", 1, requests.size());
        
        assertTrue("valid document", response.isValid());
        assertEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidationResponse().getValidation().getStatus());
    }
    
    /**
     * Negative test for signer 3 were an OCSP response is signed by an un matching private key
     * and returns the status GOOD for the signer 3 certificate.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testSigner3_withOnlyOCSP_anotherKey() throws Exception {
        LOG.info("testSigner3_withOnlyOCSP_anotherKey");

        final ArrayList<OCSPReq> requests = new ArrayList<>();
        XAdESValidator instance = new XAdESValidator() {
            @Override
            protected OCSPResponse doQueryOCSPResponder(URL url, OCSPReq request) throws IOException, OCSPException {
                try {
                    requests.add(request);
                    
                    // Create response signed by anotherKeyPair but including the rootcaCert
                    return convert(new OCSPResponseBuilder()
                            .addResponse(new OcspRespObject(new CertificateID(new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)), rootcaCert, signer3Cert.getSerialNumber()), CertificateStatus.GOOD))
                            .setResponseSignerCertificate(new JcaX509CertificateConverter().getCertificate(rootcaCert))
                            .setIssuerPrivateKey(anotherKeyPair.getPrivate()) 
                            .setChain(new X509CertificateHolder[] {rootcaCert}).build());
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            }
        };
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
        config.setProperty("REVOCATION_CHECKING", "true");
       
        instance.init(4715, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-307-1");
        DocumentValidationResponse response = validateXML(instance, 307, signedXml3, requestContext);
        
        assertEquals("OCSP calls", 1, requests.size());
        
        assertNotEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidationResponse().getValidation().getStatus());
        assertFalse("valid document", response.isValid());
    }
    
    /**
     * Negative test for signer 3 were querying the OCSP responder fails.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testSigner3_withOnlyOCSP_unavailable() throws Exception {
        LOG.info("testSigner3_withOnlyOCSP_unavailable");

        final ArrayList<OCSPReq> requests = new ArrayList<>();
        XAdESValidator instance = new XAdESValidator() {
            @Override
            protected OCSPResponse doQueryOCSPResponder(URL url, OCSPReq request) throws IOException, OCSPException {
                requests.add(request);
                // The default implementation will fail as http://ocsp.example.com can not be reached
                return super.doQueryOCSPResponder(url, request);
            }
        };
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
        config.setProperty("REVOCATION_CHECKING", "true");
       
        instance.init(4715, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-307-1");
        DocumentValidationResponse response = validateXML(instance, 307, signedXml3, requestContext);
        
        assertEquals("OCSP calls", 1, requests.size());
        
        assertFalse("valid document", response.isValid());
        assertNotEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidationResponse().getValidation().getStatus());
    }

    /**
     * Negative test for signer 3 were an OCSP response is signed by the CA
     * and returns the status REVOKED for the signer 3 certificate.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testSigner3_withOnlyOCSP_revoked() throws Exception {
        LOG.info("testSigner3_withOnlyOCSP_revoked");

        final ArrayList<OCSPReq> requests = new ArrayList<>();
        XAdESValidator instance = new XAdESValidator() {
            @Override
            protected OCSPResponse doQueryOCSPResponder(URL url, OCSPReq request) throws IOException, OCSPException {
                try {
                    requests.add(request);
                    
                    // Create response signed by the CA and with REVOKED status
                    return convert(new OCSPResponseBuilder()
                            .addResponse(new OcspRespObject(new CertificateID(new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)), rootcaCert, signer3Cert.getSerialNumber()), new RevokedStatus(new Date(1389884758000l), 1)))
                            .setResponseSignerCertificate(new JcaX509CertificateConverter().getCertificate(rootcaCert))
                            .setIssuerPrivateKey(rootcaKeyPair.getPrivate())
                            .setChain(new X509CertificateHolder[] {rootcaCert}).build());
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            }
        };
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
        config.setProperty("REVOCATION_CHECKING", "true");
       
        instance.init(4715, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-307-1");
        DocumentValidationResponse response = validateXML(instance, 307, signedXml3, requestContext);
        
        assertEquals("OCSP calls", 1, requests.size());
        
        assertFalse("valid document", response.isValid());
        assertNotEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidationResponse().getValidation().getStatus());
    }
    
    /**
     * Positive test for signer 3 were an OCSP response is signed by the CA
     * and returns the status GOOD for the signer 3 certificate.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testSigner4_withOnlyOCSP_ca_ok() throws Exception {
        LOG.info("testSigner4_withOnlyOCSP_ca_ok");
        
        final ArrayList<OCSPReq> requests = new ArrayList<>();
        XAdESValidator instance = new XAdESValidator() {
            @Override
            protected OCSPResponse doQueryOCSPResponder(URL url, OCSPReq request) throws IOException, OCSPException {
                try {
                    requests.add(request);
                    
                    // Create response signed by the sub CA2 or Root CA
                    if (request.getRequestList()[0].getCertID().matchesIssuer(subca2Cert, new BcDigestCalculatorProvider())) {
                        return convert(new OCSPResponseBuilder()
                            .addResponse(new OcspRespObject(new CertificateID(new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)), subca2Cert, signer4Cert.getSerialNumber()), CertificateStatus.GOOD))
                            .setResponseSignerCertificate(new JcaX509CertificateConverter().getCertificate(subca2Cert))
                            .setIssuerPrivateKey(subca2KeyPair.getPrivate())
                            .setChain(new X509CertificateHolder[] {subca2Cert}).build());
                    } else {
                        return convert(new OCSPResponseBuilder()
                            .addResponse(new OcspRespObject(new CertificateID(new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)), rootcaCert, subca2Cert.getSerialNumber()), CertificateStatus.GOOD))
                            .setResponseSignerCertificate(new JcaX509CertificateConverter().getCertificate(rootcaCert))
                            .setIssuerPrivateKey(rootcaKeyPair.getPrivate())
                            .setChain(new X509CertificateHolder[] {rootcaCert}).build());
                    }
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            }
        };
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
        config.setProperty("CERTIFICATES", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(subca2Cert)))));
        config.setProperty("REVOCATION_CHECKING", "true");
       
        instance.init(4716, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-407-1");
        DocumentValidationResponse response = validateXML(instance, 407, signedXml4, requestContext);
        
        assertEquals("OCSP calls", 2, requests.size());
        
        assertTrue("valid document", response.isValid());
        assertEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidationResponse().getValidation().getStatus());
    }
    
    /**
     * Positive test for signer 4 were an OCSP response is signed by external
     * responder and returns the status GOOD for the signer 4 certificate.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testSigner4_withOnlyOCSP_responder_ok() throws Exception {
        LOG.info("testSigner4_withOnlyOCSP_responder_ok");

        final ArrayList<OCSPReq> requests = new ArrayList<>();
        XAdESValidator instance = new XAdESValidator() {
            @Override
            protected OCSPResponse doQueryOCSPResponder(URL url, OCSPReq request) throws IOException, OCSPException {
                try {
                    requests.add(request);
                    
                    // SubCA 2 responder else RootCA responder
                    if (request.getRequestList()[0].getCertID().matchesIssuer(subca2Cert, new BcDigestCalculatorProvider())) {
                        return convert(new OCSPResponseBuilder()
                            .addResponse(new OcspRespObject(new CertificateID(new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)), subca2Cert, signer4Cert.getSerialNumber()), CertificateStatus.GOOD))
                            .setResponseSignerCertificate(new JcaX509CertificateConverter().getCertificate(ocspSigner2Cert))
                            .setIssuerPrivateKey(ocspSigner2KeyPair.getPrivate())
                            .setChain(new X509CertificateHolder[] {ocspSigner2Cert}).build());
                    } else {
                        return convert(new OCSPResponseBuilder()
                            .addResponse(new OcspRespObject(new CertificateID(new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)), rootcaCert, subca2Cert.getSerialNumber()), CertificateStatus.GOOD))
                            .setResponseSignerCertificate(new JcaX509CertificateConverter().getCertificate(ocspSigner1Cert))
                            .setIssuerPrivateKey(ocspSigner1KeyPair.getPrivate())
                            .setChain(new X509CertificateHolder[] {ocspSigner1Cert}).build());
                    }
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            }
        };
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
        config.setProperty("CERTIFICATES", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(subca2Cert)))));
        config.setProperty("REVOCATION_CHECKING", "true");
       
        instance.init(4715, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-407-2");
        DocumentValidationResponse response = validateXML(instance, 407, signedXml4, requestContext);
        
        assertEquals("OCSP calls", 2, requests.size());
        
        assertTrue("valid document", response.isValid());
        assertEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidationResponse().getValidation().getStatus());
    }
    

    /**
     * Negative test for signer 4 were an OCSP response is signed by the sub CA2
     * and returns the status REVOKED for the signer 4 certificate.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testSigner4_withOnlyOCSP_certRevoked() throws Exception {
        LOG.info("testSigner4_withOnlyOCSP_certRevoked");

        final ArrayList<OCSPReq> requests = new ArrayList<>();
        XAdESValidator instance = new XAdESValidator() {
            @Override
            protected OCSPResponse doQueryOCSPResponder(URL url, OCSPReq request) throws IOException, OCSPException {
                try {
                    requests.add(request);
                    
                    // SubCA 2 responder else RootCA responder
                    if (request.getRequestList()[0].getCertID().matchesIssuer(subca2Cert, new BcDigestCalculatorProvider())) {
                        return convert(new OCSPResponseBuilder()
                            .addResponse(new OcspRespObject(new CertificateID(new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)), subca2Cert, signer4Cert.getSerialNumber()), new RevokedStatus(new Date(1389884758000l), 1)))
                            .setResponseSignerCertificate(new JcaX509CertificateConverter().getCertificate(ocspSigner2Cert))
                            .setIssuerPrivateKey(ocspSigner2KeyPair.getPrivate())
                            .setChain(new X509CertificateHolder[] {ocspSigner2Cert}).build());
                    } else {
                        return convert(new OCSPResponseBuilder()
                            .addResponse(new OcspRespObject(new CertificateID(new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)), rootcaCert, subca2Cert.getSerialNumber()), CertificateStatus.GOOD))
                            .setResponseSignerCertificate(new JcaX509CertificateConverter().getCertificate(ocspSigner1Cert))
                            .setIssuerPrivateKey(ocspSigner1KeyPair.getPrivate())
                            .setChain(new X509CertificateHolder[] {ocspSigner1Cert}).build());
                    }
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            }
        };
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
        config.setProperty("CERTIFICATES", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(subca2Cert)))));
        config.setProperty("REVOCATION_CHECKING", "true");
       
        instance.init(4715, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-407-4");
        DocumentValidationResponse response = validateXML(instance, 407, signedXml4, requestContext);
        
        assertEquals("OCSP calls", 2, requests.size());
        
        assertFalse("valid document", response.isValid());
        assertNotEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidationResponse().getValidation().getStatus());
    }
    
    /**
     * Negative test for signer 4 were an OCSP response is signed by the Root CA
     * and returns the status REVOKED for the sub CA 2 certificate.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testSigner4_withOnlyOCSP_caRevoked() throws Exception {
        LOG.info("testSigner4_withOnlyOCSP_caRevoked");

        final ArrayList<OCSPReq> requests = new ArrayList<>();
        XAdESValidator instance = new XAdESValidator() {
            @Override
            protected OCSPResponse doQueryOCSPResponder(URL url, OCSPReq request) throws IOException, OCSPException {
                try {
                    requests.add(request);
                    
                    // SubCA 2 responder else RootCA responder
                    if (request.getRequestList()[0].getCertID().matchesIssuer(subca2Cert, new BcDigestCalculatorProvider())) {
                        return convert(new OCSPResponseBuilder()
                            .addResponse(new OcspRespObject(new CertificateID(new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)), subca2Cert, signer4Cert.getSerialNumber()), CertificateStatus.GOOD))
                            .setResponseSignerCertificate(new JcaX509CertificateConverter().getCertificate(ocspSigner2Cert))
                            .setIssuerPrivateKey(ocspSigner2KeyPair.getPrivate())
                            .setChain(new X509CertificateHolder[] {ocspSigner2Cert}).build());
                    } else {
                        return convert(new OCSPResponseBuilder()
                            .addResponse(new OcspRespObject(new CertificateID(new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)), rootcaCert, subca2Cert.getSerialNumber()), new RevokedStatus(new Date(1389884758000l), 1)))
                            .setResponseSignerCertificate(new JcaX509CertificateConverter().getCertificate(ocspSigner1Cert))
                            .setIssuerPrivateKey(ocspSigner1KeyPair.getPrivate())
                            .setChain(new X509CertificateHolder[] {ocspSigner1Cert}).build());
                    }
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            }
        };
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
        config.setProperty("CERTIFICATES", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(subca2Cert)))));
        config.setProperty("REVOCATION_CHECKING", "true");
       
        instance.init(4715, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-407-4");
        DocumentValidationResponse response = validateXML(instance, 407, signedXml4, requestContext);
        
        assertTrue("OCSP calls: " + requests.size(), requests.size() == 1 || requests.size() == 2);
        
        assertFalse("valid document", response.isValid());
        assertNotEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidationResponse().getValidation().getStatus());
    }
    
    /**
     * Positive test for signer 5 were OCSP is unable and falls back to CDP
     * were CRL is ok.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testSigner5_withOCSPandCDP_ok() throws Exception {
        LOG.info("testSigner5_withOCSPandCDP_ok");

        final ArrayList<OCSPReq> requests = new ArrayList<>();
        XAdESValidator instance = new XAdESValidator() {
            @Override
            protected OCSPResponse doQueryOCSPResponder(URL url, OCSPReq request) throws IOException, OCSPException {
                requests.add(request);
                throw new IOException("Simulating OCSP unavailable");
            }
        };
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
        config.setProperty("REVOCATION_CHECKING", "true");
       
        instance.init(4715, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-307-1");
        DocumentValidationResponse response = validateXML(instance, 307, signedXml5, requestContext);
        
        assertEquals("OCSP calls", 1, requests.size());
        
        assertTrue("valid document", response.isValid());
        assertEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidationResponse().getValidation().getStatus());
    }
    
    /**
     * Negative test for signer 5 were OCSP is unable and falls back to CDP
     * were signer is revoked in CRL.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testSigner5_withOCSPandCDP_revoked() throws Exception {
        LOG.info("testSigner5_withOCSPandCDP_revoked");

        updateCRLs(rootcaCRLSigner5Revoked, subca1CRLEmpty);
        
        final ArrayList<OCSPReq> requests = new ArrayList<>();
        XAdESValidator instance = new XAdESValidator() {
            @Override
            protected OCSPResponse doQueryOCSPResponder(URL url, OCSPReq request) throws IOException, OCSPException {
                requests.add(request);
                throw new IOException("Simulating OCSP unavailable");
            }
        };
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TRUSTANCHORS", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
        config.setProperty("REVOCATION_CHECKING", "true");
       
        instance.init(4715, config, null, null);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-307-1");
        DocumentValidationResponse response = validateXML(instance, 307, signedXml5, requestContext);
        
        assertEquals("OCSP calls", 1, requests.size());
        
        assertFalse("valid document", response.isValid());
        assertNotEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidationResponse().getValidation().getStatus());
    }
    
    /**
     * Test validating a form T-signed document with adequate trust anchor.
     * 
     * @throws Exception
     */
    @Test
    public void testSigner1formT() throws Exception {
        LOG.info("signer1, form T");

        XAdESValidator instance = new XAdESValidator();
        WorkerConfig config = new WorkerConfig();
               
        config.setProperty("TRUSTANCHORS", TRUSTANCHORS_FORM_T);
        config.setProperty("REVOCATION_CHECKING", "false");

        updateCRLs(rootcaCRLEmpty, subca1CRLEmpty);
        
        instance.init(4716, config, null, null);

        // override the time stamp token verifier to use recording verification provider
        instance.setTimeStampVerificationProviderImplementation(ProxyTimeStampTokenVerificationProvider.class);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-308-0");
        DocumentValidationResponse response = validateXML(instance, 308, SIGNED_XML_FORM_T, requestContext);
        
        assertTrue("valid document", response.isValid());
        assertNotNull("returned signer cert", response.getCertificateValidationResponse().getValidation().getCertificate());
        assertEquals("cert validation status", Validation.Status.VALID, response.getCertificateValidationResponse().getValidation().getStatus());
        assertTrue("time stamp verification performed", ProxyTimeStampTokenVerificationProvider.performedVerification);
    }
    
    /**
     * Test validating a form T-signed document with lacking TSA trust anchor. Should be invalid.
     * 
     * @throws Exception
     */
    @Test
    public void testSigner1formTMissingTrustAnchor() throws Exception {
        LOG.info("signer1, form T");

        XAdESValidator instance = new XAdESValidator();
        WorkerConfig config = new WorkerConfig();
               
        config.setProperty("TRUSTANCHORS", TRUSTANCHORS_MISSING_TS);
        config.setProperty("REVOCATION_CHECKING", "false");
        
        updateCRLs(rootcaCRLEmpty, subca1CRLEmpty);
        
        instance.init(4716, config, null, null);

        // override the time stamp token verifier to use recording verification provider
        instance.setTimeStampVerificationProviderImplementation(ProxyTimeStampTokenVerificationProvider.class);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-308-0");
        DocumentValidationResponse response = validateXML(instance, 308, SIGNED_XML_FORM_T, requestContext);
        
        assertFalse("invalid document", response.isValid());
        assertTrue("time stamp verification performed", ProxyTimeStampTokenVerificationProvider.performedVerification);
    }
    
    /**
     * Test validating document with intermediate certificates in the signing certificate chain.
     * 
     * @throws Exception
     */
    @Test
    public void testSigner2formTwithIntermediateCert() throws Exception {
        LOG.info("signer2, form T with intermediate TSA CA cert included in config");
        
        final XAdESValidator instance = new XAdESValidator();
        final WorkerConfig config = new WorkerConfig();
        
        config.setProperty("TRUSTANCHORS", TRUSTANCHORS_FORM_T);
        config.setProperty("CERTIFICATES", SUB_CA_CERT);
        config.setProperty("REVOCATION_CHECKING", "false");
        
        updateCRLs(rootcaCRLEmpty, subca1CRLEmpty);
        
        instance.init(4717, config, null, null);

        // override the time stamp token verifier to use recording verification provider
        ProxyTimeStampTokenVerificationProvider.performedVerification = false;
        instance.setTimeStampVerificationProviderImplementation(ProxyTimeStampTokenVerificationProvider.class);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-309-0");
        DocumentValidationResponse response = validateXML(instance, 309, SIGNED_XML_WITH_INTERMEDIATE_TS_CERT, requestContext);
        
        assertTrue("valid document", response.isValid());
        assertTrue("time stamp verification performed", ProxyTimeStampTokenVerificationProvider.performedVerification);
    }
    
    /**
     * Test validating document with intermediate certificates in the signing certificate chain.
     * 
     * @throws Exception
     */
    @Test
    public void testSigner2formTwithIntermediateCertNotConfigured() throws Exception {
        LOG.info("signer2, form T with intermediate TSA CA cert, not included in config");
        
        final XAdESValidator instance = new XAdESValidator();
        final WorkerConfig config = new WorkerConfig();
        
        config.setProperty("TRUSTANCHORS", TRUSTANCHORS_FORM_T);
        // "CERTIFICATES", SUB_CA_CERT not configured
        config.setProperty("REVOCATION_CHECKING", "false");
        
        updateCRLs(rootcaCRLEmpty, subca1CRLEmpty);
        
        instance.init(4717, config, null, null);

        // override the time stamp token verifier to use recording verification provider
        ProxyTimeStampTokenVerificationProvider.performedVerification = false;
        instance.setTimeStampVerificationProviderImplementation(ProxyTimeStampTokenVerificationProvider.class);
        
        RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-309-0");
        DocumentValidationResponse response = validateXML(instance, 309, SIGNED_XML_WITH_INTERMEDIATE_TS_CERT, requestContext);
        
        assertTrue("valid document", response.isValid());
        assertTrue("time stamp verification performed", ProxyTimeStampTokenVerificationProvider.performedVerification);
    }

    /**
     * Tests that a document with a DOCTYPE is not allowed.
     * @throws Exception
     */
    @Test
    @SuppressWarnings("ThrowableResultIgnored")
    public void testDTDNotAllowed() throws Exception {
        LOG.info("testDTDNotAllowed");
        try {
            XAdESValidator instance = new XAdESValidator();
            WorkerConfig config = new WorkerConfig();
            config.setProperty("TRUSTANCHORS", new String(CertTools.getPemFromCertificateChain(Arrays.<Certificate>asList(new JcaX509CertificateConverter().getCertificate(rootcaCert)))));
            config.setProperty("REVOCATION_CHECKING", "false");

            updateCRLs(rootcaCRLEmpty, subca1CRLEmpty);

            instance.init(4714, config, null, null);

            RequestContext requestContext = new RequestContext();
            requestContext.put(RequestContext.TRANSACTION_ID, "0000-300-0");
            validateXML(instance, 300, SIGNED_XML_DOCTYPE, requestContext);

            fail("Should have thrown IllegalRequestException as the document contained a DTD");
        } catch (SignServerException expected) {
            if (expected.getCause() instanceof SAXParseException) {
                if (!expected.getCause().getMessage().contains("DOCTYPE")) {
                    LOG.error("Wrong exception message", expected);
                    fail("Should be error about doctype: " + expected.getMessage());
                }
            } else {
                LOG.error("Wrong exception cause", expected);
                fail("Expected SAXParseException but was: " + expected);
            }
        }
    }

    /**
     * Updating the CRL files with the values specified.
     * @param rootcaCRL value for the the Root CA CRL
     * @param subcaCRL value for the Sub CA CRL
     * @throws Exception in case of IO errors
     */
    private void updateCRLs(final X509CRLHolder rootcaCRL, final X509CRLHolder subcaCRL) throws IOException {
        FileUtils.writeByteArrayToFile(rootcaCRLFile, rootcaCRL.getEncoded());
        FileUtils.writeByteArrayToFile(subca1CRLFile, subcaCRL.getEncoded());
    }
    
    @AfterClass
    public static void tearDownClass() {
        if (FileUtils.deleteQuietly(rootcaCRLFile)) {
            LOG.info("Removed rootcaCRLFile file:- " + rootcaCRLFile);
        }
        if (FileUtils.deleteQuietly(subca1CRLFile)) {
            LOG.info("Removed subca1CRLFile file:- " + subca1CRLFile);
        }
    }
    
    /**
     * Implementation of {@link xades4j.providers.TimeStampVerificationProvider} enabling tracking performed verification.
     */
    private static class ProxyTimeStampTokenVerificationProvider extends DefaultTimeStampVerificationProvider {

        static boolean performedVerification = false;
        
        @Inject
        public ProxyTimeStampTokenVerificationProvider(
                CertificateValidationProvider certificateValidationProvider,
                MessageDigestEngineProvider messageDigestProvider) {
            super(certificateValidationProvider, messageDigestProvider);
        }

        @Override
        public Date verifyToken(byte[] arg0, byte[] arg1)
                throws TimeStampTokenVerificationException {
            performedVerification = true;
            final Date ret;
            try {
                ret = super.verifyToken(arg0, arg1);
            } catch (TimeStampTokenVerificationException e) {
                LOG.info("Timestamp verification failed: " + e.getMessage());
                throw e;
            }
            
            return ret;
        }
    }
    
    private DocumentValidationResponse validateXML(XAdESValidator instance, int requestId, String xml, RequestContext requestContext) throws Exception {
        try (CloseableReadableData requestData = ModulesTestCase.createRequestData(xml.getBytes(StandardCharsets.UTF_8))) {
            DocumentValidationRequest request = new DocumentValidationRequest(requestId, requestData);
            return (DocumentValidationResponse) instance.processData(request, requestContext);
        }
    }

}