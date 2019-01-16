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
package org.signserver.testutils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Properties;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.signserver.client.cli.defaultimpl.AliasKeyManager;
import static org.junit.Assert.*;
import org.signserver.common.util.PathUtil;

/**
 * Class containing utility methods used to simplify testing.
 *
 * @author Philip Vendil 21 okt 2007
 * @version $Id$
 */
public class TestUtils {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(TestUtils.class);
    
    private Properties buildConfig;
    
    /** Expected values in the signingCertificate CMS attribute */
    private static final String SIGNING_CERT_OID = "1.2.840.113549.1.9.16.2.12";
    private static final String SIGNING_CERT_V2_OID = "1.2.840.113549.1.9.16.2.47";
    private static final String CN_OID = "2.5.4.3";
    private static final String OU_OID = "2.5.4.11";
    private static final String O_OID = "2.5.4.10";
    private static final String C_OID = "2.5.4.6";
    private static final String CN = "DSS Root CA 10";
    private static final String OU = "Testing";
    private static final String O = "SignServer";
    private static final String C = "SE";
    
    public SSLSocketFactory setupSSLTruststore() throws KeyStoreException, IOException, FileNotFoundException, NoSuchAlgorithmException, CertificateException, KeyManagementException, UnrecoverableKeyException {
        // This does not work on JDK 7 / GlassFish 3
//        System.setProperty("javax.net.ssl.trustStore", trustStore);
//        System.setProperty("javax.net.ssl.trustStorePassword",
//                getTrustStorePassword());
        //System.setProperty("javax.net.ssl.keyStore", "../../p12/testadmin.jks");
        //System.setProperty("javax.net.ssl.keyStorePassword", "foo123");
        
        // Instead set the socket factory
        KeyStore truststore = loadKeyStore(getTruststoreFile(), getTrustStorePassword());
        return setDefaultSocketFactory(truststore, null, null, null);
    }
    
    private static KeyStore loadKeyStore(final File truststoreFile,
            final String truststorePassword) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException {
        LOG.debug("Loading truststore: " + truststoreFile.getCanonicalPath());
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(new FileInputStream(truststoreFile), truststorePassword.toCharArray());
        return keystore;
    }

    private static SSLSocketFactory setDefaultSocketFactory(final KeyStore truststore,
            final KeyStore keystore, String keyAlias, char[] keystorePassword) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException, UnrecoverableKeyException {

        final TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(truststore);

        final KeyManager[] keyManagers;
        if (keystore == null) {
            keyManagers = null;
        } else {
            if (keyAlias == null) {
                keyAlias = keystore.aliases().nextElement();
            }
            final KeyManagerFactory kKeyManagerFactory
                    = KeyManagerFactory.getInstance("SunX509");
            kKeyManagerFactory.init(keystore, keystorePassword);
            keyManagers = kKeyManagerFactory.getKeyManagers();
            for (int i = 0; i < keyManagers.length; i++) {
                if (keyManagers[i] instanceof X509KeyManager) {
                    keyManagers[i] = new AliasKeyManager(
                            (X509KeyManager) keyManagers[i], keyAlias);
                }
            }
        }

        final SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyManagers, tmf.getTrustManagers(), new SecureRandom());

        SSLSocketFactory factory = context.getSocketFactory();
        
        return factory;
    }
    
    private Properties getBuildConfig() {
        if (buildConfig == null) {
            buildConfig = new Properties();
            File confFile1 = new File("../../signserver_deploy.properties");
            File confFile2 = new File("../../conf/signserver_deploy.properties");
            try {
                if (confFile1.exists()) {
                    buildConfig.load(new FileInputStream(confFile1));
                } else {
                    buildConfig.load(new FileInputStream(confFile2));
                }
            } catch (FileNotFoundException ignored) {
                LOG.debug("No signserver_deploy.properties");
            } catch (IOException ex) {
                LOG.error("Not using signserver_deploy.properties: " + ex.getMessage());
            }
        }
        return buildConfig;
    }
    
    public File getTruststoreFile() throws FileNotFoundException {
        return new File(PathUtil.getAppHome(), "p12/truststore.jks");
    }
     
    public String getTrustStorePassword() {
        return getBuildConfig().getProperty("java.trustpassword", "changeit");
    }
    
    public static void checkSigningCertificateAttribute(final Attribute attr,
                                                        final X509Certificate cert,
                                                        final String digestAlg,
                                                        final boolean useESSCertIDv2)
            throws Exception {    
        assertEquals("Invalid OID for content",
                useESSCertIDv2 ? SIGNING_CERT_V2_OID : SIGNING_CERT_OID,
                attr.getAttrType().getId());

        // calculate expected hash
        final byte[] digest = MessageDigest.getInstance(digestAlg).digest(cert.getEncoded());
        
        final ASN1Set vals = attr.getAttrValues();
        
        if (useESSCertIDv2) {
            final SigningCertificateV2 sc =
                    SigningCertificateV2.getInstance(vals.getObjectAt(0));
            final ESSCertIDv2 certId = sc.getCerts()[0];
            
            final IssuerSerial is = certId.getIssuerSerial();
        
            assertTrue("Hash doesn't match", Arrays.equals(digest, certId.getCertHash()));
            assertEquals("Serial number doesn't match", cert.getSerialNumber(),
                         is.getSerial().getValue());
        } else {
            final SigningCertificate sc = SigningCertificate.getInstance(vals.getObjectAt(0));
            final ESSCertID certId = sc.getCerts()[0];
            
            final IssuerSerial is = certId.getIssuerSerial();
        
            assertTrue("Hash doesn't match", Arrays.equals(digest, certId.getCertHash()));
            assertEquals("Serial number doesn't match", cert.getSerialNumber(),
                         is.getSerial().getValue());
        }
    }
}
