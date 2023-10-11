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
package xades4j.providers.impl;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.signserver.module.cmssigner.FilteredSignedAttributeTableGenerator;

/**
 * Mocked XADES4J TimeStampTokenProvider used for testing the XAdESSigner.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class MockedTimeStampTokenProvider extends AbstractTimeStampTokenProvider {


    /** Logger for this class. */
    private static Logger LOG = Logger.getLogger(MockedTimeStampTokenProvider.class);
    
    private final PrivateKey tsaPrivateKey;
    private final X509Certificate tsaCert;

    /**
     * Hard-coded test time stamp.
     */
    public static final long TIMESTAMP = 1379686957;
    
    /**
     * Counters of performed timestamps and verifications.
     */
    private static boolean requestedTimeStampToken;
    private static boolean performedTimeStampVerification;

    public MockedTimeStampTokenProvider(PrivateKey tsaPrivateKey, X509Certificate tsaCert) {
        super(new DefaultMessageDigestProvider());
        this.tsaPrivateKey = tsaPrivateKey;
        this.tsaCert = tsaCert;
    }

    /**
     * Resets the mock timestamp and verification counters.
     */
    public static void reset() {
        requestedTimeStampToken = false;
        performedTimeStampVerification = false;
    }
    
    /**
     * Check if a time stamp token has been requested (since resetting).
     * 
     * @return True if a token has been requested.
     */
    public static boolean hasRequestedTimeStampToken() {
        return requestedTimeStampToken;
    }
    
    /**
     * Check if time stamp verification has been performed (since resetting).
     * 
     * @return True if a token has been requested to be verified.
     */
    public static boolean hasPerformedTimeStampVerification() {
        return performedTimeStampVerification;
    }

    @Override
    byte[] getResponse(byte[] timeStampRequest) {
        try {
            requestedTimeStampToken = true;

            // Generate time-stamp token and response
            TimeStampRequest request = new TimeStampRequest(timeStampRequest);
            final TimeStampTokenGenerator timeStampTokenGen = getTimeStampTokenGenerator(/*timeStampRequest*/);
            final TimeStampResponseGenerator timeStampResponseGen = new TimeStampResponseGenerator(timeStampTokenGen, TSPAlgorithms.ALLOWED, null, null);
            TimeStampResponse timeStampResponse = timeStampResponseGen.generateGrantedResponse(request, new BigInteger("123456"), new Date(TIMESTAMP), "Operation Okidoki");
            return timeStampResponse.getEncoded();
        } catch (OperatorCreationException | CertificateEncodingException | IllegalArgumentException | TSPException | IOException ex) {
            throw new RuntimeException("Failure in mock: " + ex.getMessage(), ex);
        }
    }

    private TimeStampTokenGenerator getTimeStampTokenGenerator(/*byte[] timeStampRequest*/) throws OperatorCreationException, CertificateEncodingException, IllegalArgumentException, TSPException {
        DigestCalculatorProvider calcProv = new BcDigestCalculatorProvider();
        DigestCalculator calc = calcProv.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));

        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(tsaPrivateKey);
        JcaSignerInfoGeneratorBuilder sigb = new JcaSignerInfoGeneratorBuilder(calcProv);
        sigb.setSignedAttributeGenerator(new FilteredSignedAttributeTableGenerator(Arrays.asList(CMSAttributes.signingTime)));
        SignerInfoGenerator sig = sigb.build(cs, tsaCert);

        return new TimeStampTokenGenerator(sig, calc, new ASN1ObjectIdentifier("1.3.6.1.4.1.22408.1.2.3.45"));
    }
}
