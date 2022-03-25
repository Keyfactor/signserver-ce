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
package org.signserver.server.cryptotokens;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.CertTools;
import org.cesecore.util.query.Criteria;
import org.cesecore.util.query.QueryCriteria;
import org.cesecore.util.query.elems.RelationalOperator;
import org.cesecore.util.query.elems.Term;
import static org.junit.Assert.*;
import org.signserver.common.AbstractCertReqData;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.OperationUnsupportedException;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.QueryException;
import org.signserver.common.SignServerException;
import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.ejb.interfaces.WorkerSessionRemote;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.testutils.ModulesTestCase;

/**
 * Generic CryptoToken tests. This class can be extended and the abstract
 * methods implemented to test a specific CryptoToken implementation.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public abstract class CryptoTokenTestBase {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(CryptoTokenTestBase.class);
    
    protected ModulesTestCase testCase = new ModulesTestCase();
    
    public abstract TokenSearchResults searchTokenEntries(final int startIndex, final int max, final QueryCriteria qc, final boolean includeData) 
            throws InvalidWorkerIdException, AuthorizationDeniedException, SignServerException, OperationUnsupportedException, CryptoTokenOfflineException, QueryException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter;
    
    public abstract void generateKey(String keyType, String keySpec, String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, SignServerException;
    public abstract boolean removeKey(String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, SignServerException, KeyStoreException;
    
    protected abstract void importCertificateChain(List<Certificate> chain, String alias)
            throws CryptoTokenOfflineException, IllegalArgumentException,
                   CertificateException, CertificateEncodingException,
                   OperationUnsupportedException;
    
    protected abstract ICertReqData genCertificateRequest(ISignerCertReqInfo req,
                                                               boolean explicitEccParameters,
                                                               String alias)
            throws CryptoTokenOfflineException, InvalidWorkerIdException;
    
    protected abstract List<Certificate> getCertificateChain(String alias)
            throws CryptoTokenOfflineException, InvalidWorkerIdException;

//    private static final Set<String> longFields;
//    private static final Set<String> dateFields;
//    private static final Set<RelationalOperator> noArgOps;
//    private static final Set<String> allowedFields;
    
    // TODO: This could be useful in some accessible helper class
    
//    static {
//        longFields = new HashSet<String>();
//        longFields.add(AuditRecordData.FIELD_SEQUENCENUMBER);
//        
//        dateFields = new HashSet<String>();
//        dateFields.add(AuditRecordData.FIELD_TIMESTAMP);
//        
//        noArgOps = new HashSet<RelationalOperator>();
//        noArgOps.add(RelationalOperator.NULL);
//        noArgOps.add(RelationalOperator.NOTNULL);
//        
//        // allowed fields from CESeCore
//        // TODO: should maybe define this in CESeCore?
//        allowedFields = new HashSet<String>();
//        allowedFields.add(AuditRecordData.FIELD_ADDITIONAL_DETAILS);
//        allowedFields.add(AuditRecordData.FIELD_AUTHENTICATION_TOKEN);
//        allowedFields.add(AuditRecordData.FIELD_CUSTOM_ID);
//        allowedFields.add(AuditRecordData.FIELD_EVENTSTATUS);
//        allowedFields.add(AuditRecordData.FIELD_EVENTTYPE);
//        allowedFields.add(AuditRecordData.FIELD_MODULE);
//        allowedFields.add(AuditRecordData.FIELD_NODEID);
//        allowedFields.add(AuditRecordData.FIELD_SEARCHABLE_DETAIL1);
//        allowedFields.add(AuditRecordData.FIELD_SEARCHABLE_DETAIL2);
//        allowedFields.add(AuditRecordData.FIELD_SERVICE);
//        allowedFields.add(AuditRecordData.FIELD_SEQUENCENUMBER);
//        allowedFields.add(AuditRecordData.FIELD_TIMESTAMP);
//    }
    public static final String FIELD_ALIAS = "alias";

    public Properties getConfig() {
        return testCase.getConfig();
    }
    
    public WorkerSessionRemote getWorkerSession() {
        return testCase.getWorkerSession();
    }

    public void removeWorker(int workerId) throws Exception {
        testCase.removeWorker(workerId);
    }

    /**
     * TODO tests...
     * 
     * Checks that the entries are returned in the same order for each call (given no entries added or removed).
     * @param existingKey
     * @throws Exception 
     */
    public void searchTokenEntriesHelper(final String existingKey) throws Exception {
        
        final String[] testAliases = new String[] { "alias-14", "alias-13", "alias-5", "alias-10", "alias-2", "alias-1" };
        
        try {
            // First it is empty
            TokenSearchResults searchResults = searchTokenEntries(0, Integer.MAX_VALUE, QueryCriteria.create(), true);
            LinkedList<String> aliases = new LinkedList<>();
            for (TokenEntry entry : searchResults.getEntries()) {
                aliases.add(entry.getAlias());
            }
            LOG.info("Existing aliases: " + aliases);
            assertEquals("no entries except the test key yet", 2, searchResults.getEntries().size());
            assertFalse("no more entries", searchResults.isMoreEntriesAvailable());

            // Now create some entries
            for (String alias : testAliases) {
                generateKey("RSA", "1024", alias);
            }

            searchResults = searchTokenEntries(0, Integer.MAX_VALUE, QueryCriteria.create(), true);
            aliases = new LinkedList<>();
            for (TokenEntry entry : searchResults.getEntries()) {
                aliases.add(entry.getAlias());
            }
            
            // Check that all aliases are there
            for (String alias : testAliases) {
                assertTrue("should contain " + alias + " but only had " + aliases,
                        aliases.contains(alias));
            }
            assertTrue("should contain " + existingKey + " but only had " + aliases,
                        aliases.contains(existingKey));
            assertEquals("no more aliases than the expected in " + aliases,
                    testAliases.length + 2, aliases.size());
            
            final String[] allAliases = aliases.toArray(new String[0]);
            LOG.info("allAliases: " + Arrays.toString(allAliases));

            // Search 1 at the time
            searchResults = searchTokenEntries(0, 1, QueryCriteria.create(), true);
            aliases = new LinkedList<>();
            for (TokenEntry entry : searchResults.getEntries()) {
                aliases.add(entry.getAlias());
            }
            assertArrayEquals(new String[] { allAliases[0] }, aliases.toArray());
            assertTrue("more entries available", searchResults.isMoreEntriesAvailable());

            // Search 1 at the time
            searchResults = searchTokenEntries(1, 1, QueryCriteria.create(), true);
            aliases = new LinkedList<>();
            for (TokenEntry entry : searchResults.getEntries()) {
                aliases.add(entry.getAlias());
            }
            assertArrayEquals(new String[] { allAliases[1] }, aliases.toArray());
            assertTrue("more entries available", searchResults.isMoreEntriesAvailable());

            // Search 4 at the time, and then there are no more
            searchResults = searchTokenEntries(3, 5, QueryCriteria.create(), true);
            aliases = new LinkedList<>();
            for (TokenEntry entry : searchResults.getEntries()) {
                aliases.add(entry.getAlias());
            }
            assertArrayEquals(new String[] { allAliases[3], allAliases[4], allAliases[5], allAliases[6], allAliases[7] }, aliases.toArray());
            assertFalse("no more entries available", searchResults.isMoreEntriesAvailable());

            // Querying out of index returns empty results
            searchResults = searchTokenEntries(8, 1, QueryCriteria.create(), true);
            aliases = new LinkedList<>();
            for (TokenEntry entry : searchResults.getEntries()) {
                aliases.add(entry.getAlias());
            }
            assertArrayEquals(new String[] {}, aliases.toArray());
            assertFalse("no more entries available", searchResults.isMoreEntriesAvailable());
            
            // Query one specific entry
            searchResults = searchTokenEntries(0, Integer.MAX_VALUE, QueryCriteria.create().add(new Term(RelationalOperator.EQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), allAliases[3])), true);
            aliases = new LinkedList<>();
            for (TokenEntry entry : searchResults.getEntries()) {
                aliases.add(entry.getAlias());
            }
            assertArrayEquals(new String[] { allAliases[3] }, aliases.toArray());
            assertFalse("no more entries available", searchResults.isMoreEntriesAvailable());
            
            // Query two specific entries
            searchResults = searchTokenEntries(0, Integer.MAX_VALUE, QueryCriteria.create().add(Criteria.or(new Term(RelationalOperator.EQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), allAliases[3]), new Term(RelationalOperator.EQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), allAliases[1]))), true);
            aliases = new LinkedList<>();
            for (TokenEntry entry : searchResults.getEntries()) {
                aliases.add(entry.getAlias());
            }
            assertArrayEquals(new String[] { allAliases[1], allAliases[3] }, aliases.toArray());
            assertFalse("no more entries available", searchResults.isMoreEntriesAvailable());
            
            // Query all except 3 and 1
            searchResults = searchTokenEntries(0, Integer.MAX_VALUE, QueryCriteria.create().add(Criteria.and(new Term(RelationalOperator.NEQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), allAliases[3]), new Term(RelationalOperator.NEQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), allAliases[1]))), true);
            aliases = new LinkedList<>();
            for (TokenEntry entry : searchResults.getEntries()) {
                aliases.add(entry.getAlias());
            }
            assertArrayEquals(new String[] { allAliases[0], allAliases[2], allAliases[4], allAliases[5], allAliases[6], allAliases[7] }, aliases.toArray());
            assertFalse("no more entries available", searchResults.isMoreEntriesAvailable());
            
            // Query all except 3 and 1, only get the 4 first entries
            searchResults = searchTokenEntries(0, 4, QueryCriteria.create().add(Criteria.and(new Term(RelationalOperator.NEQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), allAliases[3]), new Term(RelationalOperator.NEQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), allAliases[1]))), true);
            aliases = new LinkedList<>();
            for (TokenEntry entry : searchResults.getEntries()) {
                aliases.add(entry.getAlias());
            }
            assertArrayEquals(new String[] { allAliases[0], allAliases[2], allAliases[4], allAliases[5] }, aliases.toArray());
            assertTrue("more entries available", searchResults.isMoreEntriesAvailable());
            
            // Query all except 3 and 1 (same as last), but get the next two
            searchResults = searchTokenEntries(4, Integer.MAX_VALUE, QueryCriteria.create().add(Criteria.and(new Term(RelationalOperator.NEQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), allAliases[3]), new Term(RelationalOperator.NEQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), allAliases[1]))), true);
            aliases = new LinkedList<>();
            for (TokenEntry entry : searchResults.getEntries()) {
                aliases.add(entry.getAlias());
            }
            assertArrayEquals(new String[] { allAliases[6], allAliases[7] }, aliases.toArray());
            assertFalse("no more entries available", searchResults.isMoreEntriesAvailable());

            // Query with both AND and OR
            // "alias-14", "alias-13", "alias-5", "alias-10", "alias-2", "alias-1"
            // (alias EQ "alias-2") OR (alias LIKE alias-1% AND alias NEQ alias-13) => alias-14, alias-10, alias-2, alias-1
            searchResults = searchTokenEntries(0, Integer.MAX_VALUE, QueryCriteria.create().add(Criteria.or(
                new Term(RelationalOperator.EQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), "alias-2"),
                Criteria.and(
                    new Term(RelationalOperator.LIKE, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), "alias-1%"),
                    new Term(RelationalOperator.NEQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), "alias-13")
                ))
            ), true);
            aliases = new LinkedList<>();
            for (TokenEntry entry : searchResults.getEntries()) {
                aliases.add(entry.getAlias());
            }
            String[] expected = new String[] { "alias-14", "alias-10", "alias-2", "alias-1" };
            Arrays.sort(expected);
            String[] actual = aliases.toArray(new String[0]);
            Arrays.sort(actual);
            assertArrayEquals(expected, actual);
            assertFalse("no more entries available", searchResults.isMoreEntriesAvailable());
            
            // Check that data is not included
            boolean includeData = false;
            searchResults = searchTokenEntries(0, Integer.MAX_VALUE, QueryCriteria.create().add(new Term(RelationalOperator.EQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), allAliases[3])), includeData);
            TokenEntry entry = searchResults.getEntries().iterator().next();
            assertNull("chain", entry.getChain());
            assertNull("parsedChain", entry.getParsedChain());
            assertNull("date", entry.getCreationDate());
            assertNull("trustedCert", entry.getTrustedCertificate());
            assertNull("parsedTrustedCert", entry.getParsedTrustedCertificate());
            assertTrue("info", entry.getInfo() == null || entry.getInfo().isEmpty());
            
        } finally {
            for (String alias : testAliases) {
                try {
                    removeKey(alias);
                } catch (Exception ex) {
                    LOG.error("Failed to remove alias: " + alias + ": " + ex.getLocalizedMessage());
                }
            }
        }
    }
    
    protected void importCertificateChainHelper(final String existingKey) 
            throws NoSuchAlgorithmException, NoSuchProviderException,
                   OperatorCreationException, IOException, CertificateException,
                   CryptoTokenOfflineException, 
                   IllegalArgumentException, 
                   CertificateEncodingException, 
                   OperationUnsupportedException, InvalidWorkerIdException, 
                   SignServerException, AuthorizationDeniedException, QueryException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter {
        final String additionalAlias = "additionalKey";
        
        try {
            final ISignerCertReqInfo req =
                    new PKCS10CertReqInfo("SHA1WithRSA", "CN=imported, organizationIdentifier=12345, O=Test", null);
            AbstractCertReqData reqData =
                    (AbstractCertReqData) genCertificateRequest(req, false, existingKey);

            // Issue certificate
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
            KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
            final X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=Test Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

            // import certficate chain
            importCertificateChain(Arrays.asList(CertTools.getCertfromByteArray(cert.getEncoded())), existingKey);

            // Find the certificate chain
            TokenSearchResults searchResults = searchTokenEntries(0, Integer.MAX_VALUE, QueryCriteria.create().add(new Term(RelationalOperator.EQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), existingKey)), true);
            assertEquals("Entry exists", 1, searchResults.getEntries().size());
            Certificate[] chain = searchResults.getEntries().iterator().next().getParsedChain();
            assertEquals("Number of certs", 1, chain.length);
            Certificate foundCert = chain[0];

            assertTrue("Imported cert",
                    Arrays.equals(foundCert.getEncoded(), cert.getEncoded()));

            generateKey("RSA", "1024", additionalAlias);

            // Isse additional certificate
            reqData =
                    (AbstractCertReqData) genCertificateRequest(req, false, additionalAlias);

            csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
            issuerKeyPair = CryptoUtils.generateRSA(512);
            final X509CertificateHolder newCert = new X509v3CertificateBuilder(new X500Name("CN=Test Issuer2"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

            // import certficate chain
            importCertificateChain(Arrays.asList(CertTools.getCertfromByteArray(newCert.getEncoded())), additionalAlias);

            // check that previously imported cert chain is un-affected
            searchResults = searchTokenEntries(0, Integer.MAX_VALUE, QueryCriteria.create().add(new Term(RelationalOperator.EQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), existingKey)), true);
            assertEquals("Entry exists", 1, searchResults.getEntries().size());
            chain = searchResults.getEntries().iterator().next().getParsedChain();
            assertEquals("Number of certs", 1, chain.length);
            foundCert = chain[0];

            assertTrue("Imported cert",
                    Arrays.equals(foundCert.getEncoded(), cert.getEncoded()));

            
            // Test that it is not allowed to import a certificate for
            // an other key
            try {
                final Certificate[] chainForExistingKey = chain;
                final String aliasForAnOtherKey = additionalAlias;
                importCertificateChain(Arrays.asList(chainForExistingKey), aliasForAnOtherKey);
                fail("Should have thrown exception about the key not matching");
            } catch (CryptoTokenOfflineException expected) {
                assertTrue("ex: " + expected.getMessage(), expected.getMessage().contains("does not match"));
            }
            
        } finally {
            try {
                removeKey(additionalAlias);
            } catch (KeyStoreException ex) {
                LOG.error("Failed to remove additional key");
            }
        }
    }
    
    /**
     * Tests export of certificate chain. First imports a generate certificate
     * chain and then checks that it can be read back. Then imports an other
     * chain and checks again.
     * @param existingKey entry to use
     */
    protected void exportCertificatesHelper(final String existingKey) throws CryptoTokenOfflineException,
            KeyStoreException, InvalidWorkerIdException, SignServerException,
            IllegalArgumentException, CertificateException,
            CertificateEncodingException, OperationUnsupportedException,
            NoSuchAlgorithmException, NoSuchProviderException,
            OperatorCreationException, IOException, QueryException, OperationUnsupportedException, AuthorizationDeniedException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter {
        
        final ISignerCertReqInfo req = new PKCS10CertReqInfo("SHA1WithRSA", "CN=imported, organizationIdentifier=12345, O=Test", null);
        final AbstractCertReqData reqData = (AbstractCertReqData) genCertificateRequest(req, false, existingKey);

        // Generate a certificate chain that we will try to import and later export
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        final X509CertificateHolder issuerCert = new JcaX509v3CertificateBuilder(new X500Name("CN=Test Import/Export CA"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(3650)), new X500Name("CN=Test Import/Export CA"), issuerKeyPair.getPublic()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
        final X509CertificateHolder subjectCert1 = new X509v3CertificateBuilder(new X500Name("CN=Test Import/Export CA"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), new X500Name("CN=Test Import/Export 1"), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));
        final X509CertificateHolder subjectCert2 = new X509v3CertificateBuilder(new X500Name("CN=Test Import/Export CA"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), new X500Name("CN=Test Import/Export 2"), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

        // Import certficate chain 1
        importCertificateChain(Arrays.asList(CertTools.getCertfromByteArray(subjectCert1.getEncoded()), CertTools.getCertfromByteArray(issuerCert.getEncoded())), existingKey);

        // Find the entry
        TokenSearchResults searchResults = searchTokenEntries(0, Integer.MAX_VALUE, QueryCriteria.create().add(new Term(RelationalOperator.EQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), existingKey)), true);
        LinkedList<String> aliases = new LinkedList<>();
        for (TokenEntry entry : searchResults.getEntries()) {
            aliases.add(entry.getAlias());
        }
        assertArrayEquals(new String[] { existingKey }, aliases.toArray());
        TokenEntry entry = searchResults.getEntries().iterator().next();
        Certificate[] parsedChain = entry.getParsedChain();

        assertEquals("right subject", new JcaX509CertificateConverter().getCertificate(subjectCert1).getSubjectX500Principal().getName(), ((X509Certificate) parsedChain[0]).getSubjectX500Principal().getName());
        assertEquals("right issuer", new JcaX509CertificateConverter().getCertificate(issuerCert).getSubjectX500Principal().getName(), ((X509Certificate) parsedChain[1]).getSubjectX500Principal().getName());

        // Import certificate chain 2
        importCertificateChain(Arrays.asList(CertTools.getCertfromByteArray(subjectCert2.getEncoded()), CertTools.getCertfromByteArray(issuerCert.getEncoded())), existingKey);

        // Find the entry
        searchResults = searchTokenEntries(0, Integer.MAX_VALUE, QueryCriteria.create().add(new Term(RelationalOperator.EQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), existingKey)), true);
        entry = searchResults.getEntries().iterator().next();
        parsedChain = entry.getParsedChain();

        assertEquals("right subject", new JcaX509CertificateConverter().getCertificate(subjectCert2).getSubjectX500Principal().getName(), ((X509Certificate) parsedChain[0]).getSubjectX500Principal().getName());
        assertEquals("right issuer", new JcaX509CertificateConverter().getCertificate(issuerCert).getSubjectX500Principal().getName(), ((X509Certificate) parsedChain[1]).getSubjectX500Principal().getName());
    }
    
    /**
     * Tests that the removeKey method works as expected.
     *
     * Tests: non-existing key and removal of existing key
     * 
     */
    protected void removeKeyHelper() throws CryptoTokenOfflineException, InvalidWorkerIdException, AuthorizationDeniedException, SignServerException, OperationUnsupportedException, QueryException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter {
        final String additionalAlias = "additionalKey-removeKeyHelper";
        final String nonexistingAlias = "removeKeyHelper-nonExistingKey123";
        
        
        // Assert that SignServerException("none-existing") is thrown for none-existing key alias
        try {
            final boolean result = removeKey(nonexistingAlias);
            fail("removeKey should have thrown SignServerException but instead returned " + result);
        } catch (SignServerException ex) {
            assertEquals("Exception message", "No such alias in token: " + nonexistingAlias, ex.getMessage());
        } catch (KeyStoreException ex) {
            LOG.error("KeyStoreException", ex);
            fail ("removeKey should have thrown SignServerException but instead thrown KeyStoreException: " + ex.getMessage());
        }
        
        try {
            // Get current number of keys before
            final TokenSearchResults keysBefore = searchTokenEntries(0, Integer.MAX_VALUE, QueryCriteria.create(), false);
            LOG.debug("Keys before (" + keysBefore.getEntries().size() + "): " + keysBefore.getEntries());

            // Generate one key to work with
            generateKey("RSA", "1024", additionalAlias);
            TokenSearchResults keysNow = searchTokenEntries(0, Integer.MAX_VALUE, QueryCriteria.create(), false);
            LOG.debug("Keys now (" + keysNow.getEntries().size() + "): " + keysNow.getEntries());
            assertEquals("Keys after generating one more", keysBefore.getEntries().size() + 1, keysNow.getEntries().size());

            // Assert that removeKey returns true
            try {
                assertTrue("removeKey return code", removeKey(additionalAlias));
            } catch (SignServerException | KeyStoreException ex) {
                LOG.error("Exception", ex);
                fail("removeKey should have returned true but throw exception: " + ex);
            }
            
            // Assert that the key is not there anymore
            TokenSearchResults keysAfter = searchTokenEntries(0, Integer.MAX_VALUE, QueryCriteria.create(), false);
            LOG.debug("Keys after (" + keysAfter.getEntries().size() + "): " + keysAfter.getEntries());
            assertFalse("Key not in list", keysAfter.getEntries().toString().contains(additionalAlias));
            assertEquals("Keys after removing it again", keysBefore.getEntries().size(), keysAfter.getEntries().size());
        } finally {
            // Try to remove the key just in case
            try {
                removeKey(additionalAlias);
            } catch (SignServerException | KeyStoreException ex) {
                LOG.error("Failed to remove additional key: " + ex.getMessage());
            }
        }
    }
    
    protected File getSignServerHome() throws FileNotFoundException {
        return testCase.getSignServerHome();
    }

}
