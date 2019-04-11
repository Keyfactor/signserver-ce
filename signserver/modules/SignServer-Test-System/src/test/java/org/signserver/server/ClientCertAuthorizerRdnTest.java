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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.common.AuthorizedClientEntry;
import org.signserver.common.MatchIssuerWithType;
import org.signserver.common.MatchSubjectWithType;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CertBuilderException;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ModulesTestCase;

/**
 * Additional System tests for the ClientCertAuthorizer with different RDN and
 * alternative names.
 *
 * For more system tests see the ClientCertAuthorizer.java.
 * 
 * For unit tests see the ClientsAuthorizationCommandUnitTest class.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ClientCertAuthorizerRdnTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ClientCertAuthorizerRdnTest.class);

    private final String ISSUER_DN_ROOTCA10 = "CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE";
    private final String ISSUER_DN_OTHERCA = "CN=DSS Other CA 01,OU=Testing,O=SignServer,C=SE";

    private static final ModulesTestCase TEST = new ModulesTestCase();
    private final CLITestHelper cli = TEST.getAdminCLI();
    private final CLITestHelper client = TEST.getClientCLI();

    private static CA ca;
    private static String dss10Path;
    
    @BeforeClass
    public static void setupClass() throws Exception {
        // Filepath
        dss10Path = TEST.getSignServerHome().getAbsolutePath() +
                                           File.separator + "res" +
                                           File.separator + "test" +
                                           File.separator + "dss10";

        // Setup CA
        Security.addProvider(new BouncyCastleProvider());
        final KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        final String ksPath = dss10Path + File.separator + "DSSRootCA10.p12";
        ks.load(new FileInputStream(ksPath), "foo123".toCharArray());

        X509Certificate caCert =
                (X509Certificate) ks.getCertificate("SignatureKeyAlias");
        PrivateKey issuerPrivKey = (PrivateKey)ks.getKey("SignatureKeyAlias", "foo123".toCharArray());
        
        ca = new CA(issuerPrivKey, caCert);
    }

    @AfterClass 
    public static void afterClass() {
        if (ca != null) {
            ca.cleanUp();
        }
    }
    
    /**
     * Helper method for performing the tests with the given authorization rules
     * and the expected working keystores/certs and the expected incorrect
     * keystores/certs.
     * @param authorizations rules
     * @param goodKeyStores that should work
     * @param badKeyStores that should not work
     * @throws Exception 
     */
    private void performTest(List<AuthorizedClientEntry> authorizations, Collection<File> goodKeyStores, Collection<File> badKeyStores) throws Exception {
        final int signerId = TEST.getSignerIdCMSSigner1();
        try {
            TEST.addCMSSigner1();
            TEST.getWorkerSession().setWorkerProperty(signerId, "AUTHTYPE", "org.signserver.server.ClientCertAuthorizer");
            TEST.getWorkerSession().reloadConfiguration(signerId);

            // Add all authorizations
            for (AuthorizedClientEntry auth : authorizations) {
                LOG.info("Adding rule " + auth);
                assertEquals("execute add for " + auth, 0,
                    cli.execute("authorizedclients", "-worker", String.valueOf(signerId),
                    "-add", 
                    "-matchSubjectWithType", auth.getMatchSubjectWithType().name(),
                    "-matchSubjectWithValue", auth.getMatchSubjectWithValue(),
                    "-matchIssuerWithType", auth.getMatchIssuerWithType().name(),
                    "-matchIssuerWithValue", auth.getMatchIssuerWithValue()));
            }
            TEST.getWorkerSession().reloadConfiguration(signerId);

            // Test signing with badKeyStore should not work
            for (File keyStore : badKeyStores) {
                LOG.info("Signing with bad keystore: " + keyStore);
                assertEquals("signdocument with bad keystore: " + keyStore.getAbsolutePath(), -2,
                        client.execute("signdocument", "-workerid", String.valueOf(signerId),
                                       "-data", "foo", "-protocol", "CLIENTWS",
                                       "-host", "localhost",
                                       "-port", "8443",
                                       "-keystore",
                                       keyStore.getAbsolutePath(),
                                       "-keystorepwd", "foo123",
                                       "-truststore",
                                       dss10Path + File.separator + "dss10_truststore.jks",
                                       "-truststorepwd", "changeit"));
            }

            // Test signing with goodKeyStore should work
            for (File keyStore : goodKeyStores) {
                LOG.info("Signing with good keystore: " + keyStore);
                assertEquals("signdocument with good keystore: " + keyStore.getAbsolutePath(), 0,
                        client.execute("signdocument", "-workerid", String.valueOf(signerId),
                                       "-data", "foo", "-protocol", "CLIENTWS",
                                       "-host", "localhost",
                                       "-port", "8443",
                                       "-keystore",
                                       keyStore.getAbsolutePath(),
                                       "-keystorepwd", "foo123",
                                       "-truststore",
                                       dss10Path + File.separator + "dss10_truststore.jks",
                                       "-truststorepwd", "changeit"));
            }
    
        } finally {
            TEST.removeWorker(signerId);
        }
    }

    /**
     * Representation of an RDN.
     */
    private static final class RDN {
        private final ASN1ObjectIdentifier oid;
        private final ASN1Encodable value;

        public RDN(ASN1ObjectIdentifier oid, ASN1Encodable value) {
            this.oid = oid;
            this.value = value;
        }
        
        public RDN(ASN1ObjectIdentifier oid, String value) {
            this.oid = oid;
            this.value = BCStyle.INSTANCE.stringToValue(oid, value);
        }

    }
    
    /**
     * Certificate Authority implementation.
     */
    private static final class CA {
        private final PrivateKey privateKey;
        private final X509Certificate certificate;
        private final Collection<File> tempFiles = new LinkedList<>();

        public CA(PrivateKey privateKey, X509Certificate certificate) {
            this.privateKey = privateKey;
            this.certificate = certificate;
        }
        
        /**
         * Issue a certificate with the provided RDNs and return the key store.
         *
         * @param subjectRdns RDNs to use in the subject
         * @return new key store
         * @throws CertBuilderException
         * @throws CertificateException
         * @throws NoSuchAlgorithmException
         * @throws NoSuchProviderException
         * @throws KeyStoreException
         * @throws IOException 
         */
        public KeyStore issueKeyStore(List<RDN> subjectRdns) throws CertBuilderException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, IOException {
            final CertBuilder builder = new CertBuilder();

            X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
            for (RDN rDn : subjectRdns) {
                nameBuilder.addRDN(rDn.oid, rDn.value);
            }

            final X500Name subject = nameBuilder.build();

            builder.setIssuerPrivateKey(privateKey);
            builder.setIssuer(certificate.getIssuerDN().getName());
            builder.setSubject(subject);
            builder.setSubjectKeyPair(CryptoUtils.generateRSA(2048));

            final PrivateKey clientPrivKey = builder.getSubjectKeyPair().getPrivate();

            final X509Certificate clientCert =
                    new JcaX509CertificateConverter().getCertificate(builder.build());
            

            final KeyStore clientKs = KeyStore.getInstance("PKCS12", "BC");
            final Certificate[] chain = {clientCert, certificate};
            
            clientKs.load(null, "foo123".toCharArray());
            clientKs.setCertificateEntry("entry", clientCert);
            clientKs.setKeyEntry("entry", clientPrivKey, "foo123".toCharArray(), chain);
            
            return clientKs;
        }
        
        /**
         * Issue a certificate with the provided RDNs and return the key store
         * file name.
         * 
         * The keystore file will be removed when cleanup is being called.
         * 
         * @param subjectRdns RDNs to use in the subject
         * @return new temporary file with the keystore
         * @throws IOException
         * @throws KeyStoreException
         * @throws NoSuchAlgorithmException
         * @throws CertificateException
         * @throws CertBuilderException
         * @throws NoSuchProviderException 
         * @see #cleanUp() 
         */
        public File issueKeyStoreFile(List<RDN> subjectRdns) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, CertBuilderException, NoSuchProviderException {
            final File file = File.createTempFile("ca-issued-client", "p12");
            tempFiles.add(file);
            
            final KeyStore keystore = issueKeyStore(subjectRdns);
            try (FileOutputStream out = new FileOutputStream(file)) {
                keystore.store(out, "foo123".toCharArray());
            }
            return file;
        }
        
        /**
         * Remove the temporary files being issued.
         */
        public void cleanUp() {
            for (File file : tempFiles) {
                if (!file.delete()) {
                    LOG.error("Unable to delete " + file.getAbsolutePath());
                }
            }
        }
    }
   
    private void standardTestOfOneRDN(MatchSubjectWithType type, ASN1ObjectIdentifier typeOid, String simpleName, String complicatedName, ASN1ObjectIdentifier otherType) throws Exception {
        
        // Setup authorizations
        final List<AuthorizedClientEntry> authorizations = Arrays.asList(
            // Basic rule to match against
            new AuthorizedClientEntry(simpleName, ISSUER_DN_ROOTCA10, type, MatchIssuerWithType.ISSUER_DN_BCSTYLE),
                
            // A rule that should not match (different CA)
            new AuthorizedClientEntry(simpleName, ISSUER_DN_OTHERCA, type, MatchIssuerWithType.ISSUER_DN_BCSTYLE),
            
            // A more complicated value to match against
            new AuthorizedClientEntry(complicatedName, ISSUER_DN_ROOTCA10, type, MatchIssuerWithType.ISSUER_DN_BCSTYLE)
        );
        
        // Certificates that should work
        final Collection<File> goodKeyStores = Arrays.asList(
                // Simplest case
                ca.issueKeyStoreFile(Arrays.asList(new RDN(typeOid, simpleName))),
                
                // One more RDN
                ca.issueKeyStoreFile(Arrays.asList(new RDN(typeOid, simpleName), new RDN(otherType, "Organization One"))),
                
                // Second CN should match
                ca.issueKeyStoreFile(Arrays.asList(new RDN(typeOid, "Name 1"), new RDN(otherType, "Organization One"), new RDN(typeOid, simpleName))),
                
                // Should also be okay with the complicated name
                ca.issueKeyStoreFile(Arrays.asList(new RDN(typeOid, complicatedName), new RDN(otherType, "Testing")))
        );
        
        // Certificates that should not work
        Collection<File> badKeyStores = Arrays.asList(
                // No CN at all
                ca.issueKeyStoreFile(Arrays.asList(new RDN(otherType, simpleName))),

                // No DN
                ca.issueKeyStoreFile(Arrays.asList(new RDN[0])),

                // Space only
                ca.issueKeyStoreFile(Arrays.asList(new RDN(typeOid, " "))),

                // Different CN
                ca.issueKeyStoreFile(Arrays.asList(new RDN(typeOid, "Admin Two"))),

                // Different case
                ca.issueKeyStoreFile(Arrays.asList(new RDN(typeOid, "Admin OnE"))), 

                // Different case and other RDN
                ca.issueKeyStoreFile(Arrays.asList(new RDN(typeOid, "Admin OnE"), new RDN(otherType, simpleName))),

                // Starting with "Admin One" but incorrect and multiple
                ca.issueKeyStoreFile(Arrays.asList(new RDN(typeOid, "Admin One2"), new RDN(typeOid, "Admin One3"), new RDN(otherType, simpleName))),
                
                // Starting with "Admin Four " but incorrect
                ca.issueKeyStoreFile(Arrays.asList(new RDN(typeOid, "Admin Four ")))
        );

        // Execute tests
        performTest(authorizations, goodKeyStores, badKeyStores);
    }
    
    // TODO: Duplicate and implement the above testSUBJECT_RDN_CN method for all other RDNs and alt names

    /**
     * Tests authorization with CommonName (CN).
     *
     * @throws Exception 
     */
    @Test
    public void testSUBJECT_RDN_CN() throws Exception {
        LOG.info("testSUBJECT_RDN_CN");
        standardTestOfOneRDN(MatchSubjectWithType.SUBJECT_RDN_CN, BCStyle.CN, "Admin One", "Admin Four !#%&,+\\$*.", BCStyle.O);
    }

    /**
     * Tests authorization with Serial number (serialNumber/SN).
     *
     * @throws Exception 
     */
    @Test
    public void testSUBJECT_RDN_SERIALNO() throws Exception {
        LOG.info("testSUBJECT_RDN_SERIALNO");
        standardTestOfOneRDN(MatchSubjectWithType.SUBJECT_RDN_SERIALNO, BCStyle.SERIALNUMBER, "Admin One", "Admin Four !#%&,+\\$*.", BCStyle.CN);
    }

    /**
     * Tests authorization with Country (C).
     *
     * @throws Exception 
     */
    @Test
    public void testSUBJECT_RDN_C() throws Exception {
        LOG.info("testSUBJECT_RDN_C");
        standardTestOfOneRDN(MatchSubjectWithType.SUBJECT_RDN_C, BCStyle.C, "Admin One", "Admin Four !#%&,+\\$*.", BCStyle.CN);
    }
    
    /**
     * Tests authorization with Domain Component (DC).
     *
     * @throws Exception 
     */
    @Test
    public void testSUBJECT_RDN_DC() throws Exception {
        LOG.info("testSUBJECT_RDN_DC");
        standardTestOfOneRDN(MatchSubjectWithType.SUBJECT_RDN_DC, BCStyle.DC, "Admin One", "Admin Four !#%&,+\\$*.", BCStyle.CN);
    }
    
    /**
     * Tests authorization with State or Province (ST).
     *
     * @throws Exception 
     */
    @Test
    public void testSUBJECT_RDN_ST() throws Exception {
        LOG.info("testSUBJECT_RDN_ST");
        standardTestOfOneRDN(MatchSubjectWithType.SUBJECT_RDN_ST, BCStyle.ST, "Admin One", "Admin Four !#%&,+\\$*.", BCStyle.CN);
    }
    
    /**
     * Tests authorization with Locality (L).
     *
     * @throws Exception 
     */
    @Test
    public void testSUBJECT_RDN_L() throws Exception {
        LOG.info("testSUBJECT_RDN_L");
        standardTestOfOneRDN(MatchSubjectWithType.SUBJECT_RDN_L, BCStyle.L, "Admin One", "Admin Four !#%&,+\\$*.", BCStyle.CN);
    }
    
    /**
     * Tests authorization with Organization (O).
     *
     * @throws Exception 
     */
    @Test
    public void testSUBJECT_RDN_O() throws Exception {
        LOG.info("testSUBJECT_RDN_O");
        standardTestOfOneRDN(MatchSubjectWithType.SUBJECT_RDN_O, BCStyle.O, "Admin One", "Admin Four !#%&,+\\$*.", BCStyle.CN);
    }
    
    /**
     * Tests authorization with Organizational Unit (OU).
     *
     * @throws Exception 
     */
    @Test
    public void testSUBJECT_RDN_OU() throws Exception {
        LOG.info("testSUBJECT_RDN_OU");
        standardTestOfOneRDN(MatchSubjectWithType.SUBJECT_RDN_OU, BCStyle.OU, "Admin One", "Admin Four !#%&,+\\$*.", BCStyle.CN);
    }
    
    /**
     * Tests authorization with Title (title).
     *
     * @throws Exception 
     */
    @Test
    public void testSUBJECT_RDN_TITLE() throws Exception {
        LOG.info("testSUBJECT_RDN_TITLE");
        standardTestOfOneRDN(MatchSubjectWithType.SUBJECT_RDN_TITLE, BCStyle.T, "Admin One", "Admin Four !#%&,+\\$*.", BCStyle.CN);
    }
    
    /**
     * Tests authorization with Unique ID (UID).
     *
     * @throws Exception 
     */
    @Test
    public void testSUBJECT_RDN_UID() throws Exception {
        LOG.info("testSUBJECT_RDN_UID");
        standardTestOfOneRDN(MatchSubjectWithType.SUBJECT_RDN_UID, BCStyle.UID, "Admin One", "Admin Four !#%&,+\\$*.", BCStyle.CN);
    }
    
    /**
     * Tests authorization with E-mail address in DN.
     *
     * @throws Exception 
     */
    @Test
    public void testSUBJECT_RDN_E() throws Exception {
        LOG.info("testSUBJECT_RDN_E");
        standardTestOfOneRDN(MatchSubjectWithType.SUBJECT_RDN_E, BCStyle.E, "Admin One", "Admin Four !#%&,+\\$*.", BCStyle.CN);
    }

    // TODO SUBJECT_ALTNAME_RFC822NAME
    // TODO SUBJECT_ALTNAME_MSUPN
}
