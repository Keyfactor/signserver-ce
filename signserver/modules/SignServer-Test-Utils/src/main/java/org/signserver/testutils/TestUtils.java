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
import java.math.BigInteger;
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
import java.util.Enumeration;
import java.util.Properties;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.signserver.client.cli.defaultimpl.AliasKeyManager;
import static org.junit.Assert.*;

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
    private static final String CN_OID = "2.5.4.3";
    private static final String OU_OID = "2.5.4.11";
    private static final String O_OID = "2.5.4.10";
    private static final String C_OID = "2.5.4.6";
    private static final String CN = "DSS Root CA 10";
    private static final String OU = "Testing";
    private static final String O = "SignServer";
    private static final String C = "SE";
    
    public void setupSSLTruststore() throws KeyStoreException, IOException, FileNotFoundException, NoSuchAlgorithmException, CertificateException, KeyManagementException, UnrecoverableKeyException {
        // This does not work on JDK 7 / GlassFish 3
//        System.setProperty("javax.net.ssl.trustStore", trustStore);
//        System.setProperty("javax.net.ssl.trustStorePassword",
//                getTrustStorePassword());
        //System.setProperty("javax.net.ssl.keyStore", "../../p12/testadmin.jks");
        //System.setProperty("javax.net.ssl.keyStorePassword", "foo123");
        
        // Instead set the socket factory
        KeyStore truststore = loadKeyStore(getTruststoreFile(), getTrustStorePassword());
        setDefaultSocketFactory(truststore, null, null, null);
    }
    
    private static KeyStore loadKeyStore(final File truststoreFile,
            final String truststorePassword) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException {
        LOG.debug("Loading truststore: " + truststoreFile.getCanonicalPath());
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(new FileInputStream(truststoreFile), truststorePassword.toCharArray());
        return keystore;
    }

    private static void setDefaultSocketFactory(final KeyStore truststore,
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
        HttpsURLConnection.setDefaultSSLSocketFactory(factory);
    }
    
    private Properties getBuildConfig() {
        if (buildConfig == null) {
            buildConfig = new Properties();
            File confFile1 = new File("../../signserver_build.properties");
            File confFile2 = new File("../../conf/signserver_build.properties");
            try {
                if (confFile1.exists()) {
                    buildConfig.load(new FileInputStream(confFile1));
                } else {
                    buildConfig.load(new FileInputStream(confFile2));
                }
            } catch (FileNotFoundException ignored) {
                LOG.debug("No signserver_build.properties");
            } catch (IOException ex) {
                LOG.error("Not using signserver_build.properties: " + ex.getMessage());
            }
        }
        return buildConfig;
    }
    
    public File getTruststoreFile() {
        return new File(System.getenv("SIGNSERVER_HOME"), "p12/truststore.jks");
    }
     
    public String getTrustStorePassword() {
        return getBuildConfig().getProperty("java.trustpassword", "changeit");
    }
    
    public static void checkSigningCertificateAttribute(final ASN1Sequence scAttr, final X509Certificate cert) throws Exception {
        final ASN1ObjectIdentifier scOid = ASN1ObjectIdentifier.getInstance(scAttr.getObjectAt(0));
        
        assertEquals("Invalid OID for content", SIGNING_CERT_OID, scOid.getId());
        
        // calculate expected hash
        final byte[] digest = MessageDigest.getInstance("SHA-1").digest(cert.getEncoded());
        
        // find hash in returned structure
        final ASN1Set set = ASN1Set.getInstance(scAttr.getObjectAt(1));
        final ASN1Sequence s1 = ASN1Sequence.getInstance(set.getObjectAt(0));
        final ASN1Sequence s2 = ASN1Sequence.getInstance(s1.getObjectAt(0));
        final ASN1Sequence s3 = ASN1Sequence.getInstance(s2.getObjectAt(0));
        final ASN1OctetString hashOctetString = ASN1OctetString.getInstance(s3.getObjectAt(0)); 
        
        assertTrue("Hash doesn't match", Arrays.equals(digest, hashOctetString.getOctets()));

        
        // find serial number in structure
        final ASN1Sequence s4 = ASN1Sequence.getInstance(s3.getObjectAt(1));
        final ASN1Integer snValue = ASN1Integer.getInstance(s4.getObjectAt(1));
        
        final BigInteger sn = cert.getSerialNumber();
        assertEquals("Serial number doesn't match", sn, snValue.getValue());
        
        // examine issuer
        final ASN1Sequence s5 = ASN1Sequence.getInstance(s4.getObjectAt(0));
        final ASN1TaggedObject obj = ASN1TaggedObject.getInstance(s5.getObjectAt(0));
        final ASN1Sequence s6 = ASN1Sequence.getInstance(obj.getObject());
        
        // expect 4 DN components in the signing cert
        assertEquals("Number of DN components", 4, s6.size());
        
        final Enumeration objects = s6.getObjects();
        while (objects.hasMoreElements()) {
            final ASN1Set component = ASN1Set.getInstance(objects.nextElement());
            final ASN1Sequence seq = ASN1Sequence.getInstance(component.getObjectAt(0));
            final ASN1ObjectIdentifier dnOid = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
            
            if (CN_OID.equals(dnOid.getId())) {
                final DERUTF8String cn = DERUTF8String.getInstance(seq.getObjectAt(1));
                assertEquals("Issuer CN doesn't match", CN, cn.getString());
            } else if (OU_OID.equals(dnOid.getId())) {
                final DERUTF8String ou = DERUTF8String.getInstance(seq.getObjectAt(1));
                assertEquals("Issuer OU doesn't match", OU, ou.getString());
            } else if (O_OID.equals(dnOid.getId())) {
                final DERUTF8String o = DERUTF8String.getInstance(seq.getObjectAt(1));
                assertEquals("Issuer O doesn't match", O, o.getString());
            } else if (C_OID.equals(dnOid.getId())) {
                final DERPrintableString c = DERPrintableString.getInstance(seq.getObjectAt(1));
                assertEquals("Issuer C doesn't match", C, c.getString());
            } else {
                fail("Unexpected issuer DN component");
            }
        }
    }
}
