/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.dnssec.signer;

import java.util.List;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.server.IServices;
import org.signserver.server.cryptotokens.ICryptoTokenV4;

/**
 * Unit tests for the ZoneFileServerSideSigner.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ZoneFileServerSideSignerUnitTest {

    private static final int WORKER = 42;

    /**
     * Test that leaving out required worker properties results in configuration
     * errors mentioning those properties.
     *
     * @throws Exception 
     */
    @Test
    public void testMissingRequiredProperties() throws Exception {
        final ZoneFileServerSideSigner instance = new ZoneFileServerSideSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };

        instance.init(WORKER, new WorkerConfig(), null, null);

        final List<String> fatalErrors = instance.getFatalErrors(null);

        assertTrue("contains error about missing ZSK_KEY_ALIAS_PREFIX",
                   fatalErrors.contains("Missing ZSK_KEY_ALIAS_PREFIX property"));
        assertTrue("contains error about missing ACTIVE_KSKS",
                   fatalErrors.contains("Missing ACTIVE_KSKS"));
    }

    /**
     * Test that more than 2 active KSKs are not accepted.
     * 
     * @throws Exception 
     */
    @Test
    public void testTooManyKsks() throws Exception {
        final ZoneFileServerSideSigner instance = new ZoneFileServerSideSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };

        final WorkerConfig config = new WorkerConfig();

        config.setProperty("ACTIVE_KSKS", "key1,key2,key3");
        instance.init(WORKER, config, null, null);

        final List<String> fatalErrors = instance.getFatalErrors(null);

        assertTrue("contains error about wrong number of KSKs",
                   fatalErrors.contains("Must specify exactly 1 or 2 active KSKs"));
    }
    
    /**
     * Test that DISABLEKEYUSAGECOUNTER as FALSE not allowed.
     *
     * @throws Exception
     */
    @Test
    public void testKeyUsageCounterDisabledFalse_ReportError() throws Exception {
        final ZoneFileServerSideSigner instance = new ZoneFileServerSideSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };

        final WorkerConfig config = new WorkerConfig();

        config.setProperty("DISABLEKEYUSAGECOUNTER", "false");
        instance.init(WORKER, config, null, null);

        final List<String> fatalErrors = instance.getFatalErrors(null);

        assertTrue("contains error about DISABLEKEYUSAGECOUNTER",
                fatalErrors.contains("DISABLEKEYUSAGECOUNTER must be TRUE for this signer"));
    }

    /**
     * Test that an empty list of KSKs is not accepted.
     * Should be treated as if ACTIVE_KSKS is not set.
     * 
     * @throws Exception 
     */
    @Test
    public void testTooFewKsks() throws Exception {
        final ZoneFileServerSideSigner instance = new ZoneFileServerSideSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };

        final WorkerConfig config = new WorkerConfig();

        config.setProperty("ACTIVE_KSKS", "");
        instance.init(WORKER, config, null, null);

        final List<String> fatalErrors = instance.getFatalErrors(null);

        assertTrue("contains error about missing ACTIVE_KSKS",
                   fatalErrors.contains("Missing ACTIVE_KSKS"));
    }

    /**
     * Test that setting a list of KSKs with extra whitespace gets trimmed
     * correctly.
     * 
     * @throws Exception 
     */
    @Test
    public void testTrimKsks() throws Exception {
        final ZoneFileServerSideSigner instance = new ZoneFileServerSideSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };

        final WorkerConfig config = new WorkerConfig();

        config.setProperty("ACTIVE_KSKS", " key1 , key2");
        config.setProperty("ZSK_KEY_ALIAS_PREFIX", "example.com_Z_");
        config.setProperty("ZONE_NAME", "example.com.");
        config.setProperty("TYPE", "PROCESSABLE");
        instance.init(WORKER, config, null, null);

        final List<String> activeKsks = instance.activeKskAliases;

        assertEquals("number of active KSKs", 2, activeKsks.size());
        assertEquals("contains expected key", "key1", activeKsks.get(0));
        assertEquals("contains expected key", "key2", activeKsks.get(1));
    }

    /**
     * Test that setting a malformed NSEC3_SALT results in an error.
     * 
     * @throws Exception 
     */
    @Test
    public void testIllegalNsec3Salt() throws Exception {
        final ZoneFileServerSideSigner instance = new ZoneFileServerSideSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };

        final WorkerConfig config = new WorkerConfig();

        config.setProperty("ACTIVE_KSKS", " key1 , key2");
        config.setProperty("ZSK_KEY_ALIAS_PREFIX", "example.com_Z_");
        config.setProperty("ZONE_NAME", "example.com.");
        config.setProperty("NSEC3_SALT", "_foobar");
        config.setProperty("TYPE", "PROCESSABLE");
        instance.init(WORKER, config, null, null);

        
        final String fatalErrors = instance.getFatalErrors(null).toString();

        assertTrue("contains error about malformed salt: " + fatalErrors,
                   fatalErrors.contains("Malformed NSEC3_SALT"));
        
    }

    /**
     * Test that setting a valid NSEC3_SALT results in no error.
     * 
     * @throws Exception 
     */
    @Test
    public void testCorrectNsec3Salt() throws Exception {
        final ZoneFileServerSideSigner instance = new ZoneFileServerSideSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };

        final WorkerConfig config = new WorkerConfig();

        config.setProperty("ACTIVE_KSKS", " key1 , key2");
        config.setProperty("ZSK_KEY_ALIAS_PREFIX", "example.com_Z_");
        config.setProperty("ZONE_NAME", "example.com.");
        config.setProperty("NSEC3_SALT", "12345678abcdef01");
        config.setProperty("TYPE", "PROCESSABLE");
        instance.init(WORKER, config, null, null);

        final List<String> fatalErrors = instance.getFatalErrors(null);
        
        assertFalse("no fatal errors", fatalErrors.toString().contains("Malformed NSEC3_SALT:"));
    }

    /**
     * Test that setting SIGNATUREALGORITHM SHA1withRSA works.
     * 
     * @throws Exception 
     */
    @Test
    public void testWithSignatureAlgorithmSHA1withRSA() throws Exception {
        internalTestWithSignatureAlgorithm("SHA1withRSA", false);
    }

    /**
     * Test that setting SIGNATUREALGORITHM SHA256withRSA works.
     * 
     * @throws Exception 
     */
    @Test
    public void testWithSignatureAlgorithmSHA256withRSA() throws Exception {
        internalTestWithSignatureAlgorithm("SHA256withRSA", false);
    }

    /**
     * Test that setting SIGNATUREALGORITHM SHA512withRSA works.
     * 
     * @throws Exception 
     */
    @Test
    public void testWithSignatureAlgorithmSHA512withRSA() throws Exception {
        internalTestWithSignatureAlgorithm("SHA512withRSA", false);
    }

    /**
     * Test that SIGNATUREALGORITHM SHA256withDSA is not supported.
     *
     * @throws Exception 
     */
    @Test
    public void testWithSignatureAlgorithmSHA256withDSANotSupported() throws Exception {
        internalTestWithSignatureAlgorithm("SHA256withDSA", true);
    }

    /**
     * Test that SIGNATUREALGORITHM SHA256withECDSA is not supported.
     *
     * @throws Exception 
     */
    @Test
    public void testWithSignatureAlgorithmSHA256withECDSANotSupported() throws Exception {
        internalTestWithSignatureAlgorithm("SHA256withECDSA", true);
    }

    /**
     * Test that setting a bogus SIGNATUREALGORITHM gives an error.
     *
     * @throws Exception 
     */
    @Test
    public void testWithBogusSignatureAlgorithm() throws Exception {
        internalTestWithSignatureAlgorithm("_unknown_", true);
    }

    /**
     * Test that setting a SIGNATUREALGORITHM with a capital With works.
     *
     * @throws Exception 
     */
    @Test
    public void testWithSignatureAlgorithmWithCapitalW() throws Exception {
        internalTestWithSignatureAlgorithm("SHA256WithRSA", false);
    }
    
    /**
     * Helper method testing with signature algorithm.
     * 
     * @throws Exception 
     */
    private void internalTestWithSignatureAlgorithm(final String sigAlg,
                                                    final boolean expectedError)
            throws Exception {
        final ZoneFileServerSideSigner instance = new ZoneFileServerSideSigner() {
            @Override
            public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                return null;
            }
        };

        final WorkerConfig config = new WorkerConfig();

        config.setProperty("ACTIVE_KSKS", " key1 , key2");
        config.setProperty("ZSK_KEY_ALIAS_PREFIX", "example.com_Z_");
        config.setProperty("ZONE_NAME", "example.com.");
        config.setProperty("TYPE", "PROCESSABLE");
        config.setProperty("SIGNATUREALGORITHM", sigAlg);
        instance.init(WORKER, config, null, null);

        final List<String> fatalErrors = instance.getFatalErrors(null);
        
        if (expectedError) {
            assertTrue("contains error: " + fatalErrors.toString(),
                       fatalErrors.contains("Unsupported signature algorithm: " +
                                            sigAlg));
        } else {
            assertFalse("fatal errors doesn't mention unsupported signature algorithm: " + fatalErrors.toString(),
                        fatalErrors.toString().contains("Unsupported signature algorithm"));
        }
    }
}
