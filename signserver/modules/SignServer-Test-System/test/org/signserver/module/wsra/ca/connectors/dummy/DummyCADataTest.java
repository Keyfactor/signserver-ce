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
package org.signserver.module.wsra.ca.connectors.dummy;

import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.security.KeyPair;
import java.util.Properties;

import junit.framework.TestCase;

import org.ejbca.util.CertTools;
import org.ejbca.util.keystore.KeyTools;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerUtil;
import org.signserver.module.wsra.ca.PKCS10CertRequestData;
import org.signserver.module.wsra.common.WSRAConstants;
import org.signserver.validationservice.common.Validation;
import org.signserver.validationservice.common.X509Certificate;
import org.signserver.validationservice.common.Validation.Status;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public class DummyCADataTest extends TestCase {

    protected void setUp() throws Exception {
        super.setUp();
        SignServerUtil.installBCProvider();
    }

    public void test01TestDummyCA() throws Exception {


        String issuerDN = "CN=test 01,C=SE";
        String filename = DummyCAData.getStoreFileName(issuerDN);
        assertNotNull(filename);
        File storeFile = new File(filename);
        if (storeFile.exists()) {
            storeFile.delete();
        }

        Properties caProps = new Properties();

        DummyCAData ca = new DummyCAData(issuerDN, caProps);

        assertNotNull(ca.getCACertificateChain());
        assertTrue(ca.getCACertificateChain().size() == 1);
        Validation v = ca.getCertificateStatus(ca.getCACertificateChain().get(0));
        assertTrue(v.getStatusMessage().equals(""));
        assertTrue(v.getStatus().equals(Status.VALID));
        assertTrue(v.getCAChain().size() == 1);
        assertTrue(v.getCertificate().getIssuer().equals(v.getCertificate().getSubject()));

        storeFile = new File(filename);
        assertTrue(storeFile.exists());

        KeyPair keys = KeyTools.genKeys("1024", "RSA");
        PKCS10CertRequestData pkcs10Req = new PKCS10CertRequestData("test1", "RFC822NAME=test@test.se", "SHA1WithRSA", "CN=test1", issuerDN, null, keys.getPublic(), keys.getPrivate(), "BC");
        X509Certificate cert = (X509Certificate) ca.requestCertificate(pkcs10Req);
        assertNotNull(cert);
        assertTrue(cert.getIssuer().equals(issuerDN));
        assertTrue(cert.getSubject().equals("CN=test1"));
        assertTrue(CertTools.getSubjectAlternativeName(cert), CertTools.getSubjectAlternativeName(cert).equalsIgnoreCase("RFC822NAME=test@test.se"));

        v = ca.getCertificateStatus(cert);
        assertTrue(v.getStatus().equals(Status.VALID));


        ca.revokeCertificate(cert, WSRAConstants.REVOKATION_REASON_NOT_REVOKED);


        ca.revokeCertificate(cert, WSRAConstants.REVOKATION_REASON_CERTIFICATEHOLD);
        v = ca.getCertificateStatus(cert);
        assertTrue(v.getStatus().equals(Status.REVOKED));
        assertNotNull(v.getRevokedDate());
        assertTrue(v.getRevokationReason() == WSRAConstants.REVOKATION_REASON_CERTIFICATEHOLD);

        ca.revokeCertificate(cert, WSRAConstants.REVOKATION_REASON_NOT_REVOKED);
        v = ca.getCertificateStatus(cert);
        assertTrue(v.getStatus().equals(Status.VALID));
        assertNull(v.getRevokedDate());
        assertTrue(v.getRevokationReason() == WSRAConstants.REVOKATION_REASON_NOT_REVOKED);

        ca.revokeCertificate(cert, WSRAConstants.REVOKATION_REASON_CERTIFICATEHOLD);
        v = ca.getCertificateStatus(cert);
        assertTrue(v.getStatus().equals(Status.REVOKED));

        ca.revokeCertificate(cert, WSRAConstants.REVOKATION_REASON_UNSPECIFIED);
        v = ca.getCertificateStatus(cert);
        assertTrue(v.getStatus().equals(Status.REVOKED));

        try {
            ca.revokeCertificate(cert, WSRAConstants.REVOKATION_REASON_NOT_REVOKED);
            assertTrue(false);
        } catch (IllegalRequestException e) {
        }


        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filename));
        ca = (DummyCAData) ois.readObject();
        assertNotNull(ca);

        v = ca.getCertificateStatus(cert);
        assertTrue(v.getStatus().equals(Status.REVOKED));

        PKCS10CertRequestData pkcs10Req2 = new PKCS10CertRequestData("test1", "RFC822NAME=test@test.se", "SHA1WithRSA", "CN=test2", issuerDN, null, keys.getPublic(), keys.getPrivate(), "BC");
        X509Certificate cert2 = (X509Certificate) ca.requestCertificate(pkcs10Req2);
        v = ca.getCertificateStatus(cert2);
        assertTrue(v.getStatus().equals(Status.VALID));
    }
}
