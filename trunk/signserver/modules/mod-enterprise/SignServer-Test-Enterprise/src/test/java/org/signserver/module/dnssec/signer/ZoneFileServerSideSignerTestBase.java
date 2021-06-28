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

import org.signserver.module.dnssec.common.RRsetId;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.jitsi.dnssec.SecurityStatus;
import org.jitsi.dnssec.validator.DnsSecVerifier;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.signserver.client.cli.ClientCLI;
import org.signserver.common.WorkerIdentifier;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ModulesTestCase;
import org.xbill.DNS.DNSKEYRecord;
import static org.xbill.DNS.DNSKEYRecord.Flags.ZONE_KEY;
import org.xbill.DNS.Master;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import static org.xbill.DNS.Type.DNSKEY;
import static org.xbill.DNS.Type.RRSIG;

/**
 * Common base class for ZoneFileServerSideSigner system tests.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public abstract class ZoneFileServerSideSignerTestBase {
    // Logger for this class
    private final static Logger LOG = Logger.getLogger(ZoneFileServerSideSignerTestBase.class);

    protected final ModulesTestCase helper = new ModulesTestCase();
    private static final CLITestHelper cli = new CLITestHelper(ClientCLI.class);

    private static final String SAMPLE_ZONE_FILE = "res/test/example.com.zone";

    /**
     * Internal helper method testing signing and verification
     * @param workerId Worker ID to use for test signer
     * @param workerName Worker name to use for test signer
     * @param cryptoWorkerId Worker ID for crypto worker (0 assumes keystore is
     *                       configured directly in the signer)
     * @param cryptoWorkerName Worker name for the crypto worker (or null if no
     *                         crypto worker is used)
     * @param expectedVerified Number of expected verified RRSIG records
     * @param numberKsks Number of KSKs to generate and setup for the worker
     * @param createOnlyOneZSK If true, only generate one ZSK (should give run-time error)
     * @param expectSigningFailure If true, expect the signing command to fail at runtime
     * @param signatureAlgorithm Signature algorithm to setup, if null use signer default
     * @param expectedAlgorithm Expected algorithm (as defined by dnsjava) of the resulting
     *                          RRSIG records
     * @throws Exception 
     */
    protected void testSigning(final int workerId,
                            final String workerName,
                            final int cryptoWorkerId,
                            final String cryptoWorkerName,
                            final int expectedVerified, 
                            final int numberKsks,
                            final boolean createOnlyOneZSK,
                            final boolean expectSigningFailure,
                            final String signatureAlgorithm,
                            final int expectedAlgorithm) throws Exception {
       final File inFile = new File(helper.getSignServerHome(), SAMPLE_ZONE_FILE);
       final File signedFile = File.createTempFile("example.com.zone", "-signed.dss");
       
       try {
            setupCryptoTokenProperties(cryptoWorkerId, false);
            helper.addZoneFileServerSideSigner(workerId, workerName, true);
            setupWorkerProperties(workerId, numberKsks, signatureAlgorithm,
                                  cryptoWorkerName);
            if (cryptoWorkerId != 0) {
                helper.getWorkerSession().reloadConfiguration(cryptoWorkerId);
            }
            helper.getWorkerSession().reloadConfiguration(workerId);

            // Create ZSK
            helper.getWorkerSession().generateSignerKey(new WorkerIdentifier(workerId),
                                                        "RSA", "2048",
                                                        "example.com_Z_1", null);
            if (!createOnlyOneZSK) {
                helper.getWorkerSession().generateSignerKey(new WorkerIdentifier(workerId),
                                                            "RSA", "2048", 
                                                            "example.com_Z_2",
                                                            null);
            }
   
            // Create KSKs
            for (int i = 0; i < numberKsks; i++) {
                final String kskAlias = "example.com_K_" + (i + 1);

                helper.getWorkerSession().generateSignerKey(new WorkerIdentifier(workerId),
                                                            "RSA", "2048",
                                                            kskAlias, null);
            }

            final int returnCode =
                    cli.execute("signdocument", "-workerid",
                                Integer.toString(workerId),
                                "-infile", inFile.getAbsolutePath(),
                                "-outfile", signedFile.getAbsolutePath(),
                                "-metadata", "ZSK_SEQUENCE_NUMBER=1");
            
            if (expectSigningFailure) {
                assertEquals("should give runtime error signing",
                             ClientCLI.RETURN_ERROR, returnCode);
            } else {
                assertEquals("should give successful signing",
                             ClientCLI.RETURN_SUCCESS, returnCode);

                final byte[] signedContent =
                        FileUtils.readFileToByteArray(signedFile);

                final Master master = new Master(new ByteArrayInputStream(signedContent));
                final List<DNSKEYRecord> zKeysFound = new LinkedList<>();
                final List<RRSIGRecord> rrSigsFound = new LinkedList<>();
                final Map<RRsetId, RRset> rrMap = new HashMap<>();

                while (true) {
                    final Record rr = master.nextRecord();

                    if (rr == null) {
                        break;
                    }

                    final RRsetId id =
                            new RRsetId(rr.getName(), rr.getDClass(), rr.getRRsetType());
                    RRset rrSet = rrMap.get(id);

                    if (rrSet == null) {
                        rrSet = new RRset(rr);
                        rrMap.put(id, rrSet);
                    } else {
                        rrSet.addRR(rr);
                    }

                    final int type = rr.getType();

                    switch (type) {
                        case DNSKEY:
                            final DNSKEYRecord dnsKey = (DNSKEYRecord) rr;

                            final int flags = dnsKey.getFlags();

                            switch (flags) {
                                case ZONE_KEY:
                                    zKeysFound.add(dnsKey);
                                    break;
                                default:
                                    // disregard
                                    break;
                            }

                            break;
                        case RRSIG:
                            rrSigsFound.add((RRSIGRecord) rr);
                            break;
                    }
                }

                final DnsSecVerifier verifier = new DnsSecVerifier();
                final List<RRSIGRecord> verifiedSigs = new LinkedList<>();
                final List<RRSIGRecord> notVerifiedSigs = new LinkedList<>();

                rrSigsFound.forEach((sig) -> {
                    final RRsetId id = new RRsetId(sig.getName(), sig.getDClass(), sig.getRRsetType());
                    final RRset set = rrMap.get(id);
                    int numberVerified = 0;
                    final int alg = sig.getAlgorithm();
                    
                    LOG.debug("Verifying signature: " + sig.getName() + ": " + id);

                    assertEquals("expected algorithm", expectedAlgorithm, alg);
                    
                    for (final DNSKEYRecord key : zKeysFound) {
                        final RRset sigSet = new RRset(set);

                        try {
                            sigSet.addRR(sig);

                            LOG.debug("checking key: " + key.toString());

                            final SecurityStatus status = verifier.verify(sigSet, key);

                            if (status == SecurityStatus.SECURE) {  
                                numberVerified++;
                            }
                        } catch (IllegalArgumentException e) {
                            LOG.debug("signature record does not match RR set");
                        }
                    }

                    if (numberVerified > 0) {
                        verifiedSigs.add(sig);
                    } else {
                        notVerifiedSigs.add(sig);
                    }
               });

                assertEquals("number verified", expectedVerified, verifiedSigs.size());
                assertTrue("no unverified signatures", notVerifiedSigs.isEmpty());
            }
        } finally {
            // Remove KSKs
            for (int i = 0; i < numberKsks; i++) {
                final String kskAlias = "example.com_K_" + (i + 1);

                helper.getWorkerSession().removeKey(new WorkerIdentifier(workerId),
                                                    kskAlias);
            }
            // Remove ZSKs
            helper.getWorkerSession().removeKey(new WorkerIdentifier(workerId),
                                                "example.com_Z_1");
            if (!createOnlyOneZSK) {
                helper.getWorkerSession().removeKey(new WorkerIdentifier(workerId),
                                                    "example.com_Z_2");
            }

            helper.removeWorker(workerId);
            if (cryptoWorkerId != 0) {
                helper.removeWorker(cryptoWorkerId);
            }
        }
   }

   protected void setupWorkerProperties(final int workerId, final int numberKsks,
                                        final String signatureAlgorithm,
                                        final String cryptoWorkerName)
           throws Exception {
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < numberKsks; i++) {
            if (i != 0) {
                sb.append(",");
            }
            sb.append("example.com_K_");
            sb.append(i + 1);
        }

        final String kskProperty = sb.toString();
        
        // Setup worker
        helper.getWorkerSession().setWorkerProperty(workerId, "ZSK_KEY_ALIAS_PREFIX", "example.com_Z_");
        helper.getWorkerSession().setWorkerProperty(workerId, "ACTIVE_KSKS", kskProperty);
        helper.getWorkerSession().setWorkerProperty(workerId, "ZONE_NAME", "example.com.");
        helper.getWorkerSession().setWorkerProperty(workerId, "NSEC3_SALT", "6dcd4ce23d88e2ee");
        if (cryptoWorkerName != null) {
            helper.getWorkerSession().setWorkerProperty(workerId, "CRYPTOTOKEN",
                                                        cryptoWorkerName);
        }
        if (signatureAlgorithm != null) {
            helper.getWorkerSession().setWorkerProperty(workerId,
                                                        "SIGNATUREALGORITHM",
                                                        signatureAlgorithm);
        }
    }
   
   protected abstract void setupCryptoTokenProperties(final int tokenId, final boolean cache) throws Exception;
}
