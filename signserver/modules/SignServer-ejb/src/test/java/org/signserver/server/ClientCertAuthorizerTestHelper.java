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
package org.signserver.server;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CertBuilderException;

/**
 * Utility functions for the client certificate authorizer tests.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ClientCertAuthorizerTestHelper {
    /**
     * Constructs a test certificate implemented by Sun classes.
     * @param serialNo to use
     * @param issuerDN to use
     * @return X.509 cert implemented by Sun
     * @throws CertBuilderException
     * @throws CertificateException
     */
    static public X509Certificate createCert(String serialNo, String issuerDN)
            throws CertBuilderException, CertificateException {
        final CertBuilder builder = new CertBuilder();
        builder.setSerialNumber(new BigInteger(serialNo, 16));
        builder.setIssuer(issuerDN);
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(builder.build());
        if (!cert.getClass().getName().startsWith("sun.")) {
            throw new RuntimeException("Error in test case, should have been Sun certificate: " + cert.getClass().getName());
        }
        return cert;
    }

    /**
     * Constructs a test certificate implemented by BC classes.
     * @param serialNo to use
     * @param issuerDN to use
     * @return X.509 cert implemented by BC
     * @throws CertBuilderException
     * @throws CertificateException
     * @throws NoSuchProviderException
     * @throws IOException
     */
    static public X509Certificate createBCCert(String serialNo, String issuerDN)
            throws CertBuilderException, CertificateException,
                   NoSuchProviderException, IOException {
        final CertBuilder builder = new CertBuilder();
        builder.setSerialNumber(new BigInteger(serialNo, 16));
        builder.setIssuer(issuerDN);
        X509CertificateHolder cert = builder.build();

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate x509cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(cert.getEncoded()));

        if (!x509cert.getClass().getName().startsWith("org.bouncycastle")) {
            throw new RuntimeException("Error in test case, should have been BC certificate: " + x509cert.getClass().getName());
        }
        return x509cert;
    }
}
