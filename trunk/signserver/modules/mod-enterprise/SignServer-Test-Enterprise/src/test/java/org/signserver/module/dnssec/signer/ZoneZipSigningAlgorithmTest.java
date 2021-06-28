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
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TimeZone;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import static junit.framework.TestCase.assertFalse;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.jitsi.dnssec.SecurityStatus;
import org.jitsi.dnssec.validator.DnsSecVerifier;
import org.junit.After;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.signserver.client.cli.ClientCLI;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerIdentifier;
import static org.signserver.module.dnssec.signer.ZoneFileServerSideSignerComplianceTest.DNSSEC_ENABLED;
import static org.signserver.module.dnssec.signer.ZoneFileServerSideSignerComplianceTest.DNSSEC_VERIFY_PATH;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ComplianceTestUtils;
import org.signserver.testutils.ComplianceTestUtils.ProcResult;
import org.signserver.testutils.ModulesTestCase;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import static org.xbill.DNS.DNSKEYRecord.Flags.ZONE_KEY;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.Master;
import org.xbill.DNS.NSRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;
import static org.xbill.DNS.Type.DNSKEY;
import static org.xbill.DNS.Type.RRSIG;
import org.xbill.DNS.Zone;

/**
 * Tests for different variations of input for signing zone files.
 *
 * @author Markus Kilås
 * @author Marcust Lundblad
 * @version $Id$
 */
@RunWith(Parameterized.class)
public class ZoneZipSigningAlgorithmTest {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(ZoneZipSigningAlgorithmTest.class);
    
    protected final ModulesTestCase helper = new ModulesTestCase();
    private static final CLITestHelper CLI = new CLITestHelper(ClientCLI.class);
    private static final FastDateFormat FDF = FastDateFormat.getInstance("yyyy-MM-dd HH:mm:ss");
    
    private static final int WORKER_ID = 18901;
    
    private static boolean complianceTestEnabled;
    private static String dnssecVerifyCommand;

    private File tempKeystoreFile;
    private File keystore;
    private static final String KEYSTORE_NAME = "testCryptoTokenP12";
    private static long fixedTimeT1;
    private static long fixedTimeT2;    

    private final Boolean clientSide;
    
    private static final String TWO_WEEKS_MIN_VALIDITY = "1209600";
    private static final String SIX_WEEKS_MIN_VALIDITY = "3628800";  // more than signature expiry period of 1 month    

    @Parameterized.Parameters(name = "{0}")
    public static Collection<Object[]> generateData() throws FileNotFoundException {
        
        final LinkedList<Object[]> data = new LinkedList<>();
        data.add(new Object[] { "server-side", false });
        data.add(new Object[] { "client-side", true });
        
        return data;
    }
    
    public ZoneZipSigningAlgorithmTest(final String title, final Boolean clientSide) throws FileNotFoundException {
        this.clientSide = clientSide;
        keystore = new File(helper.getSignServerHome(), "res/test/dss10/dss10_keystore.p12");
    }
    
    @BeforeClass
    public static void setUpClass() throws IOException {
        final Properties config = new ModulesTestCase().getConfig();
        complianceTestEnabled = !Boolean.FALSE.toString().trim().equalsIgnoreCase(config.getProperty(DNSSEC_ENABLED));
        final String dnssecVerifyPath = config.getProperty(DNSSEC_VERIFY_PATH);

        dnssecVerifyCommand
                = StringUtils.isNotBlank(dnssecVerifyPath) ? dnssecVerifyPath : "dnssec-verify";

        final Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        cal.add(Calendar.HOUR, -3);
        // Set fixed time T1        
        // round off milliseconds and remove extra milliseconds not dividable by 1000 since implementation only stores seconds 
        fixedTimeT1 = (cal.getTimeInMillis()/1000)*1000;
        LOG.info("fixtedTimeT1 " + fixedTimeT1);
        // Set fixed time T2=T1+little more (< min remaining)
        fixedTimeT2 = fixedTimeT1 + 10 * 1000; // + 10 seconds
        LOG.info("fixtedTimeT2 " + fixedTimeT2);
    }
    
    @Before
    public void setUpTest() throws FileNotFoundException, IOException {
        Assume.assumeTrue("dnssec enabled", complianceTestEnabled);
        tempKeystoreFile = File.createTempFile(KEYSTORE_NAME, ".p12");
        FileUtils.copyFile(keystore, tempKeystoreFile);

        if (clientSide) {
            helper.addSignerWithDummyKeystore("org.signserver.module.dnssec.signer.ZoneHashSigner", WORKER_ID, "ZoneZipHashSigningAlgorithmTestWorker", true);
        } else {
            helper.addSignerWithDummyKeystore("org.signserver.module.dnssec.signer.ZoneZipFileServerSideSigner", WORKER_ID, "ZoneZipSigningAlgorithmTestWorker", true);
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "MIN_REMAINING_VALIDITY", TWO_WEEKS_MIN_VALIDITY); // 2 weeks in seconds
        }
        helper.getWorkerSession().setWorkerProperty(WORKER_ID, "ZSK_KEY_ALIAS_PREFIX", "example.com_Z_");
        helper.getWorkerSession().setWorkerProperty(WORKER_ID, "ACTIVE_KSKS", "example.com_K_1");
        helper.getWorkerSession().setWorkerProperty(WORKER_ID, "ZONE_NAME", "example.com.");
        helper.getWorkerSession().setWorkerProperty(WORKER_ID, "NSEC3_SALT", "6dcd4ce23d88e2ee");
        helper.getWorkerSession().setWorkerProperty(WORKER_ID, "KEYSTOREPATH", tempKeystoreFile.getAbsolutePath());
        helper.getWorkerSession().reloadConfiguration(WORKER_ID);
    }
    
    @After
    public void tearDownTest() throws Exception {
        helper.removeWorker(WORKER_ID);
        FileUtils.deleteQuietly(tempKeystoreFile);
    }
    
    /**
     * Test Case A: All RRsets the same.
     * 
     * Test the case where all RRsets are the same in prev.zone and new.zone and
     * checks that the same RRSIGRecords are available in new.zone.
     *
     * @throws Exception 
     */
    @Test
    public void testCaseA_allRRsetsTheSame() throws Exception {
        LOG.info("testCaseA_allRRsetsTheSame");
        
        // Create Zone file -> prev.zone
        final Name name = new Name("example.com.");
        final Zone prevZone = createZone(name, true, false);
        LOG.info("prevZone:\n" + prevZone);        
       
        helper.getWorkerSession().setWorkerProperty(WORKER_ID, "FIXEDTIME", String.valueOf(fixedTimeT1));
        helper.getWorkerSession().reloadConfiguration(WORKER_ID);

        // Sign zone file -> signedZone1
        final Zone signedZone1 = sign(name, prevZone);
        LOG.info("prevZone signed:\n" + signedZone1);

        // Parse and store all RRSIGRecords (except NSEC3*) -> zone1Sigs
        final HashSet<RRSIGRecord> zone1Sigs = getSignatures(signedZone1);

        // new.zone = prev.zone;
        final Zone newZone = prevZone;        
        
        helper.getWorkerSession().setWorkerProperty(WORKER_ID, "FIXEDTIME", String.valueOf(fixedTimeT2));
        helper.getWorkerSession().reloadConfiguration(WORKER_ID);

        // Sign zone file new.zone -> signedZone2
        final Zone signedZone2 = sign(name, newZone, signedZone1);
        LOG.info("newZone signed:\n" + signedZone2);

        // Parse and store all RRSIGRecords -> zone2Sigs
        final HashSet<RRSIGRecord> zone2Sigs = getSignatures(signedZone2);

        assertEquals("number of records", zone2Sigs.size(), zone1Sigs.size());
        
        // Assert that zone1Sigs equals zone2Sigs
        LOG.info("zone1Sigs:\n" + toString(zone1Sigs));
        LOG.info("zone2Sigs:\n" + toString(zone2Sigs));
        
        for (final RRSIGRecord r : zone2Sigs) {
            if (r.getRRsetType() != Type.NSEC3 &&
                r.getRRsetType() != Type.NSEC3PARAM &&
                r.getRRsetType() != Type.DNSKEY &&
                r.getRRsetType() != Type.SOA) {
                for (final RRSIGRecord old : zone1Sigs) {
                    if (r.sameRRset(old)) {
                        assertEquals("same signature", old, r);
                    }
                }
            }
        }
        //assertEquals("zone1Sigs eq zone2Sigs", toString(zone1Sigs), toString(zone2Sigs));
        
        // Assert verifies
        assertVerifies(signedZone2.toMasterFile(), 10, DNSSEC.Algorithm.RSASHA256);
        
        // Assert verifies with dnssec-verify (with faketime and only if enabled in test-config)
        assertComplianceTest(name, signedZone2.toMasterFile(), fixedTimeT2 + 20000L);
    }

    /**
     * Test case B: added record to one RR set
     * 
     * Test that adding a record in one RR set causes the RR set to be
     * resigned compared to the old zone. All other RR sigs present and
     * identical to the old one.
     * 
     * @throws Exception 
     */
    @Test
    public void testCaseB_added() throws Exception {
        LOG.info("testCaseB_added");

        // Create Zone file -> prev.zone
        final Name name = new Name("example.com.");
        final Zone prevZone = createZone(name, true, false);

        // add an additional RRset with one record
        final Name newName = new Name("ftp." + name);
        ARecord aRecord1 = createA(newName, "192.168.0.3");
        RRset additionalRRset1 = new RRset(aRecord1);

        prevZone.addRRset(additionalRRset1);

        LOG.info("prevZone:\n" + prevZone);        
        
        helper.getWorkerSession().setWorkerProperty(WORKER_ID, "FIXEDTIME", String.valueOf(fixedTimeT1));
        helper.getWorkerSession().reloadConfiguration(WORKER_ID);

        // Sign zone file -> signedZone1
        final Zone signedZone1 = sign(name, prevZone);
        LOG.info("prevZone signed:\n" + signedZone1);

        // Parse and store all RRSIGRecords (except NSEC3*) -> zone1Sigs
        final HashSet<RRSIGRecord> zone1Sigs = getSignatures(signedZone1);

        // Create Zone file -> new.zone
        //  same as prev.zone but with some RRSets removed
        final Zone newZone = createZone(name, false, false);
        
        // add an additional RRset with  with an additional record compared to before
        final ARecord aRecord2 = createA(newName, "192.168.0.3");
        final ARecord aRecord3 = createA(newName, "192.168.0.4");
        final RRset additionalRRset2 = new RRset(aRecord2);
        additionalRRset2.addRR(aRecord3);
        
        newZone.addRRset(additionalRRset2);

        LOG.info("newZone:\n" + newZone);        
        
        helper.getWorkerSession().setWorkerProperty(WORKER_ID, "FIXEDTIME", String.valueOf(fixedTimeT2));
        helper.getWorkerSession().reloadConfiguration(WORKER_ID);

        // Sign zone file new.zone -> signedZone2
        final Zone signedZone2 = sign(name, newZone, signedZone1);
        LOG.info("newZone signed:\n" + signedZone2);

        final HashSet<RRSIGRecord> zone2Sigs = getSignatures(signedZone2);

        /* Check that all signatures in the new zone also exists in the
         * previous zone
         */
        LOG.info("zone1Sigs:\n" + toString(zone1Sigs));
        LOG.info("zone2Sigs:\n" + toString(zone2Sigs));
        
        for (final RRSIGRecord r : zone2Sigs) {
            LOG.info("checking RRSig in zone2: " + r.getName().toString() + " type: " + r.getType());
            if (r.getRRsetType() != Type.NSEC3 &&
                r.getRRsetType() != Type.NSEC3PARAM &&
                r.getRRsetType() != Type.DNSKEY &&
                r.getRRsetType() != Type.SOA) {
                
                boolean matchInPrev = false;
                for (final RRSIGRecord old : zone1Sigs) {
                    if (r.sameRRset(old)) {
                        LOG.info("compared to " + old.getName().toString() + " from zone1");
                        // if it's the ftp.example.com RRset, it should be different
                        if (r.getName().equals(newName)) {
                            assertNotEquals("changed signature", old, r);
                        } else {
                            assertEquals("same signature", old, r);
                        }
                        matchInPrev = true;
                    }
                }
                assertTrue("signature present in previous zone", matchInPrev);
            }
        }

        // Assert verifies
        assertVerifies(signedZone2.toMasterFile(), 10, DNSSEC.Algorithm.RSASHA256);

        // Assert verifies with dnssec-verify (with faketime and only if enabled in test-config)
        assertComplianceTest(name, signedZone2.toMasterFile(), fixedTimeT2 + 20000L);
    }

    /**
     * Test case B: removed record from one RR set
     * 
     * Test that removing a record in one RR set causes the RR set to be
     * resigned compared to the old zone. All other RR sigs present and
     * identical to the old one.
     * 
     * @throws Exception 
     */
    @Test
    public void testCaseB_removed() throws Exception {
        LOG.info("testCaseB_removed");

        // Create Zone file -> prev.zone
        final Name name = new Name("example.com.");
        final Zone prevZone = createZone(name, true, false);

        // add an additional record
        final Name removedName = new Name("ftp." + name);
        ARecord aRecord1 = createA(removedName, "192.168.0.3");
        ARecord aRecord2 = createA(removedName, "192.168.0.4");
        RRset additionalRRset1 = new RRset(aRecord1);
        additionalRRset1.addRR(aRecord2);

        prevZone.addRRset(additionalRRset1);

        LOG.info("prevZone:\n" + prevZone);        
        
        helper.getWorkerSession().setWorkerProperty(WORKER_ID, "FIXEDTIME", String.valueOf(fixedTimeT1));
        helper.getWorkerSession().reloadConfiguration(WORKER_ID);

        // Sign zone file -> signedZone1
        final Zone signedZone1 = sign(name, prevZone);
        LOG.info("prevZone signed:\n" + signedZone1);

        // Parse and store all RRSIGRecords (except NSEC3*) -> zone1Sigs
        final HashSet<RRSIGRecord> zone1Sigs = getSignatures(signedZone1);

        // Create Zone file -> new.zone
        //  same as prev.zone but with some RRSets removed
        final Zone newZone = createZone(name, false, false);
        
        // add an additional RRset with one less record
        final ARecord aRecord3 = createA(removedName, "192.168.0.3");
        final RRset additionalRRset2 = new RRset(aRecord3);
        
        newZone.addRRset(additionalRRset2);

        LOG.info("newZone:\n" + newZone);        
      
        helper.getWorkerSession().setWorkerProperty(WORKER_ID, "FIXEDTIME", String.valueOf(fixedTimeT2));
        helper.getWorkerSession().reloadConfiguration(WORKER_ID);

        // Sign zone file new.zone -> signedZone2
        final Zone signedZone2 = sign(name, newZone, signedZone1);
        LOG.info("newZone signed:\n" + signedZone2);

        final HashSet<RRSIGRecord> zone2Sigs = getSignatures(signedZone2);

        /* Check that all signatures in the new zone also exists in the
         * previous zone
         */
        LOG.info("zone1Sigs:\n" + toString(zone1Sigs));
        LOG.info("zone2Sigs:\n" + toString(zone2Sigs));
        
        for (final RRSIGRecord r : zone2Sigs) {
            LOG.info("checking RRSig in zone2: " + r.getName().toString() + " type: " + r.getType());
            if (r.getRRsetType() != Type.NSEC3 &&
                r.getRRsetType() != Type.NSEC3PARAM &&
                r.getRRsetType() != Type.DNSKEY &&
                r.getRRsetType() != Type.SOA) {
                
                boolean matchInPrev = false;
                for (final RRSIGRecord old : zone1Sigs) {
                    if (r.sameRRset(old)) {
                        LOG.info("compared to " + old.getName().toString() + " from zone1");
                        // if it's the ftp.example.com RRset, it should be different
                        if (r.getName().equals(removedName)) {
                            assertNotEquals("changed signature", old, r);
                        } else {
                            assertEquals("same signature", old, r);
                        }
                        matchInPrev = true;
                    }
                }
                assertTrue("signature present in previous zone", matchInPrev);
            }
        }

        // Assert verifies
        assertVerifies(signedZone2.toMasterFile(), 10, DNSSEC.Algorithm.RSASHA256);

        // Assert verifies with dnssec-verify (with faketime and only if enabled in test-config)
        assertComplianceTest(name, signedZone2.toMasterFile(), fixedTimeT2 + 20000L);
    }

    /**
     * Test case B: changed on RR set
     * 
     * Test that changing a record in one RR set causes the RR set to be
     * resigned compared to the old zone. All other RR sigs present and
     * identical to the old one.
     * 
     * @throws Exception 
     */
    @Test
    public void testCaseB_changed() throws Exception {
        LOG.info("testCaseB_changed");

        // Create Zone file -> prev.zone
        final Name name = new Name("example.com.");
        final Zone prevZone = createZone(name, true, false);

        // add an additional record
        final Name changedName = new Name("ftp." + name);
        ARecord aRecord1 = createA(changedName, "192.168.0.3");
        ARecord aRecord2 = createA(changedName, "192.168.0.4");
        RRset additionalRRset1 = new RRset(aRecord1);
        additionalRRset1.addRR(aRecord2);

        prevZone.addRRset(additionalRRset1);

        LOG.info("prevZone:\n" + prevZone);        
       
        helper.getWorkerSession().setWorkerProperty(WORKER_ID, "FIXEDTIME", String.valueOf(fixedTimeT1));
        helper.getWorkerSession().reloadConfiguration(WORKER_ID);

        // Sign zone file -> signedZone1
        final Zone signedZone1 = sign(name, prevZone);
        LOG.info("prevZone signed:\n" + signedZone1);

        // Parse and store all RRSIGRecords (except NSEC3*) -> zone1Sigs
        final HashSet<RRSIGRecord> zone1Sigs = getSignatures(signedZone1);

        // Create Zone file -> new.zone
        //  same as prev.zone but with some RRSets removed
        final Zone newZone = createZone(name, false, false);
        
        // add an additional RRset with one changed record
        final ARecord aRecord3 = createA(changedName, "192.168.0.3");
        final ARecord aRecord4 = createA(changedName, "192.168.0.5");
        final RRset additionalRRset2 = new RRset(aRecord3);
        additionalRRset2.addRR(aRecord4);
        
        newZone.addRRset(additionalRRset2);

        LOG.info("newZone:\n" + newZone);        
     
        helper.getWorkerSession().setWorkerProperty(WORKER_ID, "FIXEDTIME", String.valueOf(fixedTimeT2));
        helper.getWorkerSession().reloadConfiguration(WORKER_ID);

        // Sign zone file new.zone -> signedZone2
        final Zone signedZone2 = sign(name, newZone, signedZone1);
        LOG.info("newZone signed:\n" + signedZone2);

        final HashSet<RRSIGRecord> zone2Sigs = getSignatures(signedZone2);

        /* Check that all signatures in the new zone also exists in the
         * previous zone
         */
        LOG.info("zone1Sigs:\n" + toString(zone1Sigs));
        LOG.info("zone2Sigs:\n" + toString(zone2Sigs));
        
        for (final RRSIGRecord r : zone2Sigs) {
            LOG.info("checking RRSig in zone2: " + r.getName().toString() + " type: " + r.getType());
            if (r.getRRsetType() != Type.NSEC3 &&
                r.getRRsetType() != Type.NSEC3PARAM &&
                r.getRRsetType() != Type.DNSKEY &&
                r.getRRsetType() != Type.SOA) {
                
                boolean matchInPrev = false;
                for (final RRSIGRecord old : zone1Sigs) {
                    if (r.sameRRset(old)) {
                        LOG.info("compared to " + old.getName().toString() + " from zone1");
                        // if it's the ftp.example.com RRset, it should be different
                        if (r.getName().equals(changedName)) {
                            assertNotEquals("changed signature", old, r);
                        } else {
                            assertEquals("same signature", old, r);
                        }
                        matchInPrev = true;
                    }
                }
                assertTrue("signature present in previous zone", matchInPrev);
            }
        }

        // Assert verifies
        assertVerifies(signedZone2.toMasterFile(), 10, DNSSEC.Algorithm.RSASHA256);

        // Assert verifies with dnssec-verify (with faketime and only if enabled in test-config)
        assertComplianceTest(name, signedZone2.toMasterFile(), fixedTimeT2 + 20000L);
    }

    /**
     * Test case D: Some RRsets missing in new zone.
     * 
     * Test case where one RR set from the old zone is missing in the new one. 
     * Checks that all RR sets in the new zone signed zone where present in
     * the old one and the removed RR set is not present in the new one.
     * 
     * @throws Exception 
     */
    @Test
    public void testCaseD_removed() throws Exception {
        LOG.info("testCaseD_removed");

        // Create Zone file -> prev.zone
        final Name name = new Name("example.com.");
        final Zone prevZone = createZone(name, true, false);
        LOG.info("prevZone:\n" + prevZone);
        
        helper.getWorkerSession().setWorkerProperty(WORKER_ID, "FIXEDTIME", String.valueOf(fixedTimeT1));
        helper.getWorkerSession().reloadConfiguration(WORKER_ID);

        // Sign zone file -> signedZone1
        final Zone signedZone1 = sign(name, prevZone);
        LOG.info("prevZone signed:\n" + signedZone1);

        // Parse and store all RRSIGRecords (except NSEC3*) -> zone1Sigs
        final HashSet<RRSIGRecord> zone1Sigs = getSignatures(signedZone1);

        // Create Zone file -> new.zone
        //  same as prev.zone but with some RRSets removed
        final Zone newZone = createZone(name, false, false);
      
        helper.getWorkerSession().setWorkerProperty(WORKER_ID, "FIXEDTIME", String.valueOf(fixedTimeT2));
        helper.getWorkerSession().reloadConfiguration(WORKER_ID);

        // Sign zone file new.zone -> signedZone2
        final Zone signedZone2 = sign(name, newZone, signedZone1);
        LOG.info("newZone signed:\n" + signedZone2);

        final HashSet<RRSIGRecord> zone2Sigs = getSignatures(signedZone2);

        /* Check that all signatures in the new zone also exists in the
         * previous zone
         */
        LOG.info("zone1Sigs:\n" + toString(zone1Sigs));
        LOG.info("zone2Sigs:\n" + toString(zone2Sigs));

        final Name shouldNotBePresent = new Name("www." + name);
        
        for (final RRSIGRecord r : zone2Sigs) {
            if (r.getRRsetType() != Type.NSEC3 &&
                r.getRRsetType() != Type.NSEC3PARAM &&
                r.getRRsetType() != Type.DNSKEY &&
                r.getRRsetType() != Type.SOA) {
                boolean matchInPrev = false;
                for (final RRSIGRecord old : zone1Sigs) {
                    if (r.sameRRset(old)) {
                        assertEquals("same signature", old, r);
                        matchInPrev = true;
                    }
                }
                assertTrue("signature present in previous zone", matchInPrev);
                assertNotEquals("should not include www.", shouldNotBePresent,
                                r.getName());
            }
        }

        // Assert verifies
        assertVerifies(signedZone2.toMasterFile(), 8, DNSSEC.Algorithm.RSASHA256);

        // Assert verifies with dnssec-verify (with faketime and only if enabled in test-config)
        assertComplianceTest(name, signedZone2.toMasterFile(), fixedTimeT2 + 20000L);
    }

    /**
     * Test Case C: Some new RRset Ids.
     *
     * Test the case where some new RRsets are added in new.zone and checks that
     * the RRSIGRecords from prev.zone also are available in new.zone and that
     * new.zone has new signatures for the new RRsets.
     *
     * @throws Exception
     */
    @Test
    public void testCaseC_someNewRRsets() throws Exception {
        LOG.info("testCaseC_someNewRRsets");

        // Create Zone file -> prev.zone
        final Name name = new Name("example.com.");
        final Zone prevZone = createZone(name, true, false);
        LOG.info("prevZone:\n" + prevZone);
        
        helper.getWorkerSession().setWorkerProperty(WORKER_ID, "FIXEDTIME", String.valueOf(fixedTimeT1));
        helper.getWorkerSession().reloadConfiguration(WORKER_ID);

        // Sign zone file -> signedZone1
        final Zone signedZone1 = sign(name, prevZone);
        LOG.info("prevZone signed:\n" + signedZone1);

        // Parse and store all RRSIGRecords (except NSEC3*) -> zone1Sigs
        final HashSet<RRSIGRecord> zone1Sigs = getSignatures(signedZone1);

        // Create Zone file -> new.zone
        //  same as prev.zone but with some new RRsets        
        ARecord aRecord1 = createA(new Name("ftp." + name), "192.168.0.3");
        RRset additionalRRset1 = new RRset(aRecord1);
        ARecord aRecord2 = createA(new Name("mail." + name), "192.168.0.4");
        RRset additionalRRset2 = new RRset(aRecord2);
        prevZone.addRRset(additionalRRset1);
        prevZone.addRRset(additionalRRset2);
        final Zone newZone = prevZone;

        //  store RRsets -> additionalRRsets
        List<RRset> additionalRRsets = Arrays.asList(additionalRRset1, additionalRRset2);

        helper.getWorkerSession().setWorkerProperty(WORKER_ID, "FIXEDTIME", String.valueOf(fixedTimeT2));
        helper.getWorkerSession().reloadConfiguration(WORKER_ID);

        // Sign zone file new.zone -> signedZone2
        final Zone signedZone2 = sign(name, newZone, signedZone1);
        LOG.info("newZone signed:\n" + signedZone2);

        // Parse and store all RRSIGRecords -> zone2Sigs
        final HashSet<RRSIGRecord> zone2Sigs = getSignatures(signedZone2);

        // Assert that all zone1Sigs in zone2Sigs
        for (RRSIGRecord rrSigRecord : zone1Sigs) {
            if (rrSigRecord.getRRsetType() != Type.NSEC3 &&
                rrSigRecord.getRRsetType() != Type.NSEC3PARAM &&
                rrSigRecord.getRRsetType() != Type.DNSKEY &&
                rrSigRecord.getRRsetType() != Type.SOA) {
                assertTrue("all zone1Sigs must be present in zone2Sigs: " + rrSigRecord.toString() + ", type: " + rrSigRecord.getRRsetType(), zone2Sigs.contains(rrSigRecord));
            }
        }

        // Assert that zone2Sigs contains sigs for each in additionalRRsets and those uses time T2
        LOG.info("zone1Sigs:\n" + toString(zone1Sigs));
        LOG.info("zone2Sigs:\n" + toString(zone2Sigs));
        for (RRset rrSet : additionalRRsets) {
            final Iterator rrs = rrSet.sigs();
            while (rrs.hasNext()) {
                Record r = (Record) rrs.next();
                if (r instanceof RRSIGRecord) {
                    final RRSIGRecord sig = (RRSIGRecord) r;
                    assertTrue("zone2Sigs must contain sigs for each in additionalRRsets", zone2Sigs.contains(sig));
                    long signatureTime = sig.getTimeSigned().getTime();
                    assertEquals("zone2Sigs must contain sigs for each in additionalRRsets", signatureTime, fixedTimeT2);
                }
            }
        }

        // Assert verifies
        assertVerifies(signedZone2.toMasterFile(), 14, DNSSEC.Algorithm.RSASHA256);

        // Assert verifies with dnssec-verify (with faketime and only if enabled in test-config)
        assertComplianceTest(name, signedZone2.toMasterFile(), fixedTimeT2 + 20000L);
    }

    /**
     * Test Case: Some new RRset Ids, using next sequence number when signing
     * new zone.
     *
     * Test the case where some new RRsets are added in new.zone and checks
     * that RRsigs are generate with the second timestamp (it should be re-signed
     * using the new ZSK).
     *
     * @throws Exception
     */
    @Test
    public void testCase_someNewRRsetsNewZSKSequenceNumber() throws Exception {
        LOG.info("testCase_someNewRRsetsNewZSKSequenceNumber");

        try {
            helper.getWorkerSession().generateSignerKey(new WorkerIdentifier(WORKER_ID),
                                                        "RSA", "2048",
                                                        "example.com_Z_3", null);
            
            // Create Zone file -> prev.zone
            final Name name = new Name("example.com.");
            final Zone prevZone = createZone(name, true, false);
            LOG.info("prevZone:\n" + prevZone);
         
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "FIXEDTIME", String.valueOf(fixedTimeT1));
            helper.getWorkerSession().reloadConfiguration(WORKER_ID);

            // Sign zone file -> signedZone1
            final Zone signedZone1 = sign(name, prevZone);
            LOG.info("prevZone signed:\n" + signedZone1);

            // Parse and store all RRSIGRecords (except NSEC3*) -> zone1Sigs
            final HashSet<RRSIGRecord> zone1Sigs = getSignatures(signedZone1);

            // Create Zone file -> new.zone
            //  same as prev.zone but with some new RRsets        
            ARecord aRecord1 = createA(new Name("ftp." + name), "192.168.0.3");
            RRset additionalRRset1 = new RRset(aRecord1);
            ARecord aRecord2 = createA(new Name("mail." + name), "192.168.0.4");
            RRset additionalRRset2 = new RRset(aRecord2);
            prevZone.addRRset(additionalRRset1);
            prevZone.addRRset(additionalRRset2);
            final Zone newZone = prevZone;

            //  store RRsets -> additionalRRsets
            List<RRset> additionalRRsets = Arrays.asList(additionalRRset1, additionalRRset2);
            
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "FIXEDTIME", String.valueOf(fixedTimeT2));
            helper.getWorkerSession().reloadConfiguration(WORKER_ID);

            // Sign zone file new.zone -> signedZone2
            final Zone signedZone2 = sign(name, newZone, signedZone1, false, 2, TWO_WEEKS_MIN_VALIDITY);
            LOG.info("newZone signed:\n" + signedZone2);

            // Parse and store all RRSIGRecords -> zone2Sigs
            final HashSet<RRSIGRecord> zone2Sigs = getSignatures(signedZone2);

            // Assert that zone2Sigs contains sigs for each in additionalRRsets and those uses time T2
            LOG.info("zone1Sigs:\n" + toString(zone1Sigs));
            LOG.info("zone2Sigs:\n" + toString(zone2Sigs));
            for (RRset rrSet : additionalRRsets) {
                final Iterator rrs = rrSet.sigs();
                while (rrs.hasNext()) {
                    Record r = (Record) rrs.next();
                    if (r instanceof RRSIGRecord) {
                        final RRSIGRecord sig = (RRSIGRecord) r;
                        assertTrue("zone2Sigs must contain sigs for each in additionalRRsets", zone2Sigs.contains(sig));
                    }
                }
            }

            for (RRSIGRecord rrSig : zone2Sigs) {
                assertEquals("signature was made at new time",
                             fixedTimeT2, rrSig.getTimeSigned().getTime());
            }

            // Assert verifies
            assertVerifies(signedZone2.toMasterFile(), 14, DNSSEC.Algorithm.RSASHA256);

            // Assert verifies with dnssec-verify (with faketime and only if enabled in test-config)
            assertComplianceTest(name, signedZone2.toMasterFile(), fixedTimeT2 + 20000L);
        } finally {
            queitlyRemoveKey("example.com_K_3");
        }
    }

    /**
     * Test Case: Some new RRset Ids, using next sequence number when signing
     * new zone.
     *
     * Test the case where some new RRsets are added in new.zone and checks
     * that RRsigs are generate with the second timestamp (it should be re-signed
     * using the new ZSK).
     *
     * @throws Exception
     */
    @Test
    public void testCase_someNewRRsetsNewActiveKSKs() throws Exception {
        LOG.info("testCase_someNewRRsetsNewActiveKSKs");

        try {
            // Create Zone file -> prev.zone
            final Name name = new Name("example.com.");
            final Zone prevZone = createZone(name, true, false);
            LOG.info("prevZone:\n" + prevZone);
          
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "FIXEDTIME", String.valueOf(fixedTimeT1));
            helper.getWorkerSession().reloadConfiguration(WORKER_ID);

            // Sign zone file -> signedZone1
            final Zone signedZone1 = sign(name, prevZone);
            LOG.info("prevZone signed:\n" + signedZone1);

            // Parse and store all RRSIGRecords (except NSEC3*) -> zone1Sigs
            final HashSet<RRSIGRecord> zone1Sigs = getSignatures(signedZone1);

            // Create Zone file -> new.zone
            //  same as prev.zone but with some new RRsets        
            ARecord aRecord1 = createA(new Name("ftp." + name), "192.168.0.3");
            RRset additionalRRset1 = new RRset(aRecord1);
            ARecord aRecord2 = createA(new Name("mail." + name), "192.168.0.4");
            RRset additionalRRset2 = new RRset(aRecord2);
            prevZone.addRRset(additionalRRset1);
            prevZone.addRRset(additionalRRset2);
            final Zone newZone = prevZone;

            //  store RRsets -> additionalRRsets
            List<RRset> additionalRRsets = Arrays.asList(additionalRRset1, additionalRRset2);
           
            helper.getWorkerSession().generateSignerKey(new WorkerIdentifier(WORKER_ID),
                                                        "RSA", "2048",
                                                        "example.com_K_3", null);
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "ACTIVE_KSKS",
                                                        "example.com_K_2, example.com_K_3");
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "FIXEDTIME", String.valueOf(fixedTimeT2));
            helper.getWorkerSession().reloadConfiguration(WORKER_ID);

            // Sign zone file new.zone -> signedZone2
            final Zone signedZone2 = sign(name, newZone, signedZone1);
            LOG.info("newZone signed:\n" + signedZone2);

            // Parse and store all RRSIGRecords -> zone2Sigs
            final HashSet<RRSIGRecord> zone2Sigs = getSignatures(signedZone2);

            // Assert that zone2Sigs contains sigs for each in additionalRRsets and those uses time T2
            LOG.info("zone1Sigs:\n" + toString(zone1Sigs));
            LOG.info("zone2Sigs:\n" + toString(zone2Sigs));
            for (RRset rrSet : additionalRRsets) {
                final Iterator rrs = rrSet.sigs();
                while (rrs.hasNext()) {
                    Record r = (Record) rrs.next();
                    if (r instanceof RRSIGRecord) {
                        final RRSIGRecord sig = (RRSIGRecord) r;
                        assertTrue("zone2Sigs must contain sigs for each in additionalRRsets", zone2Sigs.contains(sig));
                        long signatureTime = sig.getTimeSigned().getTime();
                        assertEquals("signature was made at new time", signatureTime, fixedTimeT2);
                    }
                }
            }

            // Assert verifies, seems to be one additional verified signature in this case
            assertVerifies(signedZone2.toMasterFile(), 15, DNSSEC.Algorithm.RSASHA256);

            // Assert verifies with dnssec-verify (with faketime and only if enabled in test-config)
            assertComplianceTest(name, signedZone2.toMasterFile(), fixedTimeT2 + 20000L);
        } finally {
            queitlyRemoveKey("example.com_K_3");
        }
    }

    /**
     * Test Case: Some new RRset Ids, using next sequence number when signing
     * new zone.
     *
     * Test the case where some new RRsets are added in new.zone and checks
     * that RRsigs are generate with the second timestamp (it should be re-signed
     * using the new ZSK).
     *
     * @throws Exception
     */
    @Test
    public void testCase_someNewRRsetsCompletelyNewSetOfKSKs() throws Exception {
        LOG.info("testCase_someNewRRsetsCompletelyNewSetOfKSKs");

        try {
            // Create Zone file -> prev.zone
            final Name name = new Name("example.com.");
            final Zone prevZone = createZone(name, true, false);
            LOG.info("prevZone:\n" + prevZone);
           
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "FIXEDTIME", String.valueOf(fixedTimeT1));
            helper.getWorkerSession().reloadConfiguration(WORKER_ID);

            // Sign zone file -> signedZone1
            final Zone signedZone1 = sign(name, prevZone);
            LOG.info("prevZone signed:\n" + signedZone1);

            // Parse and store all RRSIGRecords (except NSEC3*) -> zone1Sigs
            final HashSet<RRSIGRecord> zone1Sigs = getSignatures(signedZone1);

            // Create Zone file -> new.zone
            //  same as prev.zone but with some new RRsets        
            ARecord aRecord1 = createA(new Name("ftp." + name), "192.168.0.3");
            RRset additionalRRset1 = new RRset(aRecord1);
            ARecord aRecord2 = createA(new Name("mail." + name), "192.168.0.4");
            RRset additionalRRset2 = new RRset(aRecord2);
            prevZone.addRRset(additionalRRset1);
            prevZone.addRRset(additionalRRset2);
            final Zone newZone = prevZone;

            //  store RRsets -> additionalRRsets
            List<RRset> additionalRRsets = Arrays.asList(additionalRRset1, additionalRRset2);
          
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "FIXEDTIME", String.valueOf(fixedTimeT2));
            helper.getWorkerSession().generateSignerKey(new WorkerIdentifier(WORKER_ID),
                                                        "RSA", "2048",
                                                        "example.com_K_3", null);
            helper.getWorkerSession().generateSignerKey(new WorkerIdentifier(WORKER_ID),
                                                        "RSA", "2048",
                                                        "example.com_K_4", null);
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "ACTIVE_KSKS",
                                                        "example.com_K_3, example.com_K_4");
            helper.getWorkerSession().reloadConfiguration(WORKER_ID);

            // Sign zone file new.zone -> signedZone2
            final Zone signedZone2 = sign(name, newZone, signedZone1);
            LOG.info("newZone signed:\n" + signedZone2);

            // Parse and store all RRSIGRecords -> zone2Sigs
            final HashSet<RRSIGRecord> zone2Sigs = getSignatures(signedZone2);

            // Assert that zone2Sigs contains sigs for each in additionalRRsets and those uses time T2
            LOG.info("zone1Sigs:\n" + toString(zone1Sigs));
            LOG.info("zone2Sigs:\n" + toString(zone2Sigs));
            for (RRset rrSet : additionalRRsets) {
                final Iterator rrs = rrSet.sigs();
                while (rrs.hasNext()) {
                    Record r = (Record) rrs.next();
                    if (r instanceof RRSIGRecord) {
                        final RRSIGRecord sig = (RRSIGRecord) r;
                        assertTrue("zone2Sigs must contain sigs for each in additionalRRsets", zone2Sigs.contains(sig));
                        long signatureTime = sig.getTimeSigned().getTime();
                        assertEquals("signature was made at new time", signatureTime, fixedTimeT2);
                    }
                }
            }

            // Assert verifies, seems to be one additional verified signature in this case
            assertVerifies(signedZone2.toMasterFile(), 15, DNSSEC.Algorithm.RSASHA256);

            // Assert verifies with dnssec-verify (with faketime and only if enabled in test-config)
            assertComplianceTest(name, signedZone2.toMasterFile(), fixedTimeT2 + 20000L);
        } finally {
            queitlyRemoveKey("example.com_K_3");
            queitlyRemoveKey("example.com_K_4");
        }
    }
    
    private void queitlyRemoveKey (final String alias) throws InvalidWorkerIdException {
        try {
            helper.getWorkerSession().removeKey(new WorkerIdentifier(WORKER_ID), alias);
        } catch (SignServerException | CryptoTokenOfflineException | KeyStoreException ex) {
            LOG.error("Unable to cleanup key: " + ex.getMessage());
        }
    }

    /**
     * Test Case C: Some new RRset Ids. Use last active KSK (K2) when re-signing.
     *
     * Test the case where some new RRsets are added in new.zone and checks that
     * the RRSIGRecords from prev.zone also are available in new.zone and that
     * new.zone has new signatures for the new RRsets.
     *
     * @throws Exception
     */
    @Test
    public void testCaseC_someNewRRsetsOneActiveKSK() throws Exception {
        LOG.info("testCaseC_someNewRRsetsOneActiveKSK");

        try {
            // Create Zone file -> prev.zone
            final Name name = new Name("example.com.");
            final Zone prevZone = createZone(name, true, false);
            LOG.info("prevZone:\n" + prevZone);
            
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "FIXEDTIME", String.valueOf(fixedTimeT1));
            helper.getWorkerSession().reloadConfiguration(WORKER_ID);

            // Sign zone file -> signedZone1
            final Zone signedZone1 = sign(name, prevZone);
            LOG.info("prevZone signed:\n" + signedZone1);

            // Parse and store all RRSIGRecords (except NSEC3*) -> zone1Sigs
            final HashSet<RRSIGRecord> zone1Sigs = getSignatures(signedZone1);

            // Create Zone file -> new.zone
            //  same as prev.zone but with some new RRsets        
            ARecord aRecord1 = createA(new Name("ftp." + name), "192.168.0.3");
            RRset additionalRRset1 = new RRset(aRecord1);
            ARecord aRecord2 = createA(new Name("mail." + name), "192.168.0.4");
            RRset additionalRRset2 = new RRset(aRecord2);
            prevZone.addRRset(additionalRRset1);
            prevZone.addRRset(additionalRRset2);
            final Zone newZone = prevZone;

            //  store RRsets -> additionalRRsets
            List<RRset> additionalRRsets = Arrays.asList(additionalRRset1, additionalRRset2);
          
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "FIXEDTIME", String.valueOf(fixedTimeT2));
            // Set active KSKs to only K2
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "ACTIVE_KSKS",
                                                        "example.com_K_2");
            helper.getWorkerSession().reloadConfiguration(WORKER_ID);

            // Sign zone file new.zone -> signedZone2
            final Zone signedZone2 = sign(name, newZone, signedZone1);
            LOG.info("newZone signed:\n" + signedZone2);

            // Parse and store all RRSIGRecords -> zone2Sigs
            final HashSet<RRSIGRecord> zone2Sigs = getSignatures(signedZone2);

            // Assert that all zone1Sigs in zone2Sigs
            for (RRSIGRecord rrSigRecord : zone1Sigs) {
                if (rrSigRecord.getRRsetType() != Type.NSEC3 &&
                    rrSigRecord.getRRsetType() != Type.NSEC3PARAM &&
                    rrSigRecord.getRRsetType() != Type.DNSKEY &&
                    rrSigRecord.getRRsetType() != Type.SOA) {
                    assertTrue("all zone1Sigs must be present in zone2Sigs: " + rrSigRecord.toString() + ", type: " + rrSigRecord.getRRsetType(), zone2Sigs.contains(rrSigRecord));
                }
            }

            // Assert that zone2Sigs contains sigs for each in additionalRRsets and those uses time T2
            LOG.info("zone1Sigs:\n" + toString(zone1Sigs));
            LOG.info("zone2Sigs:\n" + toString(zone2Sigs));
            for (RRset rrSet : additionalRRsets) {
                final Iterator rrs = rrSet.sigs();
                while (rrs.hasNext()) {
                    Record r = (Record) rrs.next();
                    if (r instanceof RRSIGRecord) {
                        final RRSIGRecord sig = (RRSIGRecord) r;
                        assertTrue("zone2Sigs must contain sigs for each in additionalRRsets", zone2Sigs.contains(sig));
                        long signatureTime = sig.getTimeSigned().getTime();
                        assertEquals("zone2Sigs must contain sigs for each in additionalRRsets", signatureTime, fixedTimeT2);
                    }
                }
            }

            // Assert verifies
            assertVerifies(signedZone2.toMasterFile(), 14, DNSSEC.Algorithm.RSASHA256);

            // Assert verifies with dnssec-verify (with faketime and only if enabled in test-config)
            assertComplianceTest(name, signedZone2.toMasterFile(), fixedTimeT2 + 20000L);
        } finally {
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "ACTIVE_KSKS",
                                                        "example.com_K_1, example.com_K_2");
            helper.getWorkerSession().reloadConfiguration(WORKER_ID);
        }
    }

    /**
     * Test Case: Some new RRset Ids. With force re-signing set.
     *
     * Test the case where some new RRsets are added in new.zone and checks
     * that all signatures where made on the new.zone and all corresponding
     * signatures from old.zone are ignored.
     *
     * @throws Exception
     */
    @Test
    public void testCase_forceResign() throws Exception {
        LOG.info("testCase_forceResign");

        // Create Zone file -> prev.zone
        final Name name = new Name("example.com.");
        final Zone prevZone = createZone(name, true, false);
        LOG.info("prevZone:\n" + prevZone);
      
        helper.getWorkerSession().setWorkerProperty(WORKER_ID, "FIXEDTIME", String.valueOf(fixedTimeT1));
        helper.getWorkerSession().reloadConfiguration(WORKER_ID);

        // Sign zone file -> signedZone1
        final Zone signedZone1 = sign(name, prevZone);
        LOG.info("prevZone signed:\n" + signedZone1);

        // Parse and store all RRSIGRecords (except NSEC3*) -> zone1Sigs
        final HashSet<RRSIGRecord> zone1Sigs = getSignatures(signedZone1);

        // Create Zone file -> new.zone
        //  same as prev.zone but with some new RRsets        
        ARecord aRecord1 = createA(new Name("ftp." + name), "192.168.0.3");
        RRset additionalRRset1 = new RRset(aRecord1);
        ARecord aRecord2 = createA(new Name("mail." + name), "192.168.0.4");
        RRset additionalRRset2 = new RRset(aRecord2);
        prevZone.addRRset(additionalRRset1);
        prevZone.addRRset(additionalRRset2);
        final Zone newZone = prevZone;
       
        helper.getWorkerSession().setWorkerProperty(WORKER_ID, "FIXEDTIME", String.valueOf(fixedTimeT2));
        helper.getWorkerSession().reloadConfiguration(WORKER_ID);

        LOG.info("newZone:\n" + newZone);

        // Sign zone file new.zone -> signedZone2, set force re-signing
        final Zone signedZone2 = sign(name, newZone, signedZone1, true);
        LOG.info("newZone signed:\n" + signedZone2);

        // Parse and store all RRSIGRecords -> zone2Sigs
        final HashSet<RRSIGRecord> zone2Sigs = getSignatures(signedZone2);

        // Assert that all zone2Sigs use time T2
        for (RRSIGRecord rrSigRecord : zone2Sigs) {
            assertEquals("using new time", fixedTimeT2,
                         rrSigRecord.getTimeSigned().getTime());
            assertFalse("not in previous signed zone",
                        zone1Sigs.contains(rrSigRecord));
        }

        // Assert verifies
        assertVerifies(signedZone2.toMasterFile(), 14, DNSSEC.Algorithm.RSASHA256);

        // Assert verifies with dnssec-verify (with faketime and only if enabled in test-config)
        assertComplianceTest(name, signedZone2.toMasterFile(), fixedTimeT2 + 20000L);
    }
    
    @Test
    public void testCaseCD_allRRsetsDifferent() throws Exception {
        LOG.info("testCaseCD_allRRsetsDifferent");

        // Create Zone file -> prev.zone
        final Name name = new Name("example.com.");
        final Zone prevZone = createZone(name, true, false);
        LOG.info("prevZone:\n" + prevZone);
        
        helper.getWorkerSession().setWorkerProperty(WORKER_ID, "FIXEDTIME", String.valueOf(fixedTimeT1));
        helper.getWorkerSession().reloadConfiguration(WORKER_ID);

        // Sign zone file -> signedZone1
        final Zone signedZone1 = sign(name, prevZone);
        LOG.info("prevZone signed:\n" + signedZone1);

        // Parse and store all RRSIGRecords (except NSEC3*) -> zone1Sigs
        final HashSet<RRSIGRecord> zone1Sigs = getSignatures(signedZone1);

        // Create Zone file -> new.zone
        // with different RR sets (different host names)
        final Zone newZone = createZone(name, true, true);
       
        helper.getWorkerSession().setWorkerProperty(WORKER_ID, "FIXEDTIME", String.valueOf(fixedTimeT2));
        helper.getWorkerSession().reloadConfiguration(WORKER_ID);

        // Sign zone file new.zone -> signedZone2
        final Zone signedZone2 = sign(name, newZone, signedZone1);
        LOG.info("newZone signed:\n" + signedZone2);

        final HashSet<RRSIGRecord> zone2Sigs = getSignatures(signedZone2);

        /* Check that all signatures in the new zone also exists in the
         * previous zone
         */
        LOG.info("zone1Sigs:\n" + toString(zone1Sigs));
        LOG.info("zone2Sigs:\n" + toString(zone2Sigs));
        
        for (final RRSIGRecord r : zone2Sigs) {
            if (r.getType() == Type.RRSIG &&
                r.getRRsetType() != Type.NSEC3 &&
                r.getRRsetType() != Type.NSEC3PARAM &&
                r.getRRsetType() != Type.DNSKEY) {
                for (final RRSIGRecord old : zone1Sigs) {
                    if (r.sameRRset(old)) {
                        assertFalse("not equal signatures",
                                    Arrays.equals(r.getSignature(),
                                                  old.getSignature()));
                    }
                }
            }
        }

        // Assert verifies
        assertVerifies(signedZone2.toMasterFile(), 10, DNSSEC.Algorithm.RSASHA256);

        // Assert verifies with dnssec-verify (with faketime and only if enabled in test-config)
        assertComplianceTest(name, signedZone2.toMasterFile(), fixedTimeT2 + 20000L);
    }
    
    /**
     * Test Case A: All RRsets the same.
     * 
     * Test the case where all RRsets are the same in prev.zone and new.zone and
     * checks that the RRsets are signed again and existing RRSIGS are not reused since validity of RRSIG is less than MIN_REMAINING_VALIDITY.
     *
     * @throws Exception 
     */
    @Test
    public void test_allRRsetsTheSame_MinRemainingValidityExpired() throws Exception {
        LOG.info("test_allRRsetsTheSame_MinRemainingValidityExpired");
        
        // Create Zone file -> prev.zone
        final Name name = new Name("example.com.");
        final Zone prevZone = createZone(name, true, false);
        LOG.info("prevZone:\n" + prevZone);        
       
        helper.getWorkerSession().setWorkerProperty(WORKER_ID, "FIXEDTIME", String.valueOf(fixedTimeT1));
        helper.getWorkerSession().reloadConfiguration(WORKER_ID);
        
        if (!clientSide) {
            helper.getWorkerSession().setWorkerProperty(WORKER_ID, "MIN_REMAINING_VALIDITY", SIX_WEEKS_MIN_VALIDITY);
            helper.getWorkerSession().reloadConfiguration(WORKER_ID);
        }

        // Sign zone file -> signedZone1
        final Zone signedZone1 = sign(name, prevZone);
        LOG.info("prevZone signed:\n" + signedZone1);

        // Parse and store all RRSIGRecords (except NSEC3*) -> zone1Sigs
        final HashSet<RRSIGRecord> zone1Sigs = getSignatures(signedZone1);

        // new.zone = prev.zone;
        final Zone newZone = prevZone;        
        
        helper.getWorkerSession().setWorkerProperty(WORKER_ID, "FIXEDTIME", String.valueOf(fixedTimeT2));
        helper.getWorkerSession().reloadConfiguration(WORKER_ID);

        // Sign zone file new.zone -> signedZone2
        final Zone signedZone2 = sign(name, newZone, signedZone1, false, 1, SIX_WEEKS_MIN_VALIDITY);
        LOG.info("newZone signed:\n" + signedZone2);

        // Parse and store all RRSIGRecords -> zone2Sigs
        final HashSet<RRSIGRecord> zone2Sigs = getSignatures(signedZone2);

        assertEquals("number of records", zone2Sigs.size(), zone1Sigs.size());
        
        // Assert that zone1Sigs equals zone2Sigs
        LOG.info("zone1Sigs:\n" + toString(zone1Sigs));
        LOG.info("zone2Sigs:\n" + toString(zone2Sigs));
        
        for (final RRSIGRecord r : zone2Sigs) {
            if (r.getRRsetType() != Type.NSEC3 &&
                r.getRRsetType() != Type.NSEC3PARAM &&
                r.getRRsetType() != Type.DNSKEY &&
                r.getRRsetType() != Type.SOA) {
                // Signature should be made at new time as MIN_REMAINING_VALIDITY is not sufficient enough to reuse signature from previously signed file
               assertEquals("signature was made at new time", fixedTimeT2, r.getTimeSigned().getTime());
            }
        }        
        
        // Assert verifies
        assertVerifies(signedZone2.toMasterFile(), 10, DNSSEC.Algorithm.RSASHA256);
        
        // Assert verifies with dnssec-verify (with faketime and only if enabled in test-config)
        assertComplianceTest(name, signedZone2.toMasterFile(), fixedTimeT2 + 20000L);
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

        tempKeystoreFile = File.createTempFile(KEYSTORE_NAME, ".p12");
        FileUtils.copyFile(keystore, tempKeystoreFile);
        helper.getWorkerSession().setWorkerProperty(workerId, "KEYSTOREPATH", tempKeystoreFile.getAbsolutePath());
        helper.getWorkerSession().reloadConfiguration(workerId);
    }

    /**
     * <pre>
     *  example.com.	86400	IN	SOA	ns1.example.com. hostmaster.example.com. 2002022401 10800 15 604800 10800
     *  example.com.	86400	IN	NS	ns1.example.com.
     *  ns1.example.com. 86400	IN	A	192.168.0.1
     *  www.example.com. 86400	IN	A	192.168.0.2
     * </pre>
     * @param nam
     * @return
     * @throws TextParseException
     * @throws IOException 
     */
    private Zone createZone(Name name, boolean includeWww,
                            boolean alternativeNames)
            throws TextParseException, IOException {
        final ArrayList<Record> records = new ArrayList<>();
        final String nsName = alternativeNames ? "ns2" : "ns1";
        final String hostmasterName =
                alternativeNames ? "hostmaster2" : "hostmaster";
        records.add(createSOA(name, nsName, hostmasterName));
        records.add(createNS(name, nsName));
        records.add(createA(new Name(nsName + "." + name), "192.168.0.1"));
        if (includeWww) {
            final String wwwName = alternativeNames ? "www2" : "www";
            records.add(createA(new Name(wwwName + "." + name), "192.168.0.2"));
        }
   
        return new Zone(name, records.toArray(new Record[0]));
    }
    
    private SOARecord createSOA(Name zoneName, String nsName,
                                String hostmasterName) throws TextParseException {
        final long refresh = 10800; // 3H
        final long retry = 15;
        final long expire = 604800; // 1w
        final long minimum = 10800; // 3H
        
        return new SOARecord(zoneName, DClass.IN, 86400,
                             new Name(nsName + "." + zoneName),
                             new Name(hostmasterName + "." + zoneName),
                             2002022401, refresh, retry, expire, minimum);
    }

    private NSRecord createNS(Name zoneName, String nsName) throws TextParseException {
        return new NSRecord(zoneName, DClass.IN, 86400,
                            new Name(nsName + "." + zoneName));
    }

    private ARecord createA(Name name, String address) throws UnknownHostException {
            return new ARecord(name, DClass.IN, 86400, InetAddress.getByName(address));
    }

    private Zone sign(Name name, Zone newZone) throws Exception {
        return sign(name, newZone, null);
    }

    private Zone sign(Name name, Zone newZone, Zone prevZone) throws Exception {
        return sign(name, newZone, prevZone, false, 1, TWO_WEEKS_MIN_VALIDITY);
    }

    private Zone sign(Name name, Zone newZone, Zone prevZone, boolean forceResign)
            throws Exception {
        return sign(name, newZone, prevZone, forceResign, 1, TWO_WEEKS_MIN_VALIDITY);
    }

    private Zone sign(Name name, Zone newZone, Zone prevZone,
                      boolean forceResign, int sequenceNumber, String minRemainingValidity)
            throws Exception {
        File inFile = null;
        File outFile = null;
        try {
            inFile = createZoneZipFile(newZone, prevZone);
            outFile = File.createTempFile("test-signed", ".zone");
            
            final int returnCode;
            
            if (clientSide) {
                returnCode = CLI.execute("signdocument", "-workerid",
                        Integer.toString(WORKER_ID),
                        "-infile", inFile.getAbsolutePath(),
                        "-outfile", outFile.getAbsolutePath(),
                        "-metadata",
                        "ZSK_SEQUENCE_NUMBER=" + Integer.toString(sequenceNumber),
                        "-clientside", "-digestalgorithm", "SHA-256", "-filetype", "ZONE_ZIP",
                        "-extraoption", "FORCE_RESIGN=" + (forceResign ? "true" : "false"),
                        "-extraoption", "ZONE_NAME=example.com.",
                        "-extraoption", "MIN_REMAINING_VALIDITY=" + minRemainingValidity
                );
            } else {
                returnCode = CLI.execute("signdocument", "-workerid",
                    Integer.toString(WORKER_ID),
                    "-infile", inFile.getAbsolutePath(),
                    "-outfile", outFile.getAbsolutePath(),
                    "-metadata",
                    "ZSK_SEQUENCE_NUMBER=" + Integer.toString(sequenceNumber),
                    "-metadata", "FORCE_RESIGN=" + (forceResign ? "true" : "false"));
            }
        
            assertEquals("signclient return code: " + CLI.getErr().toString(), 0, returnCode);
            
            return new Zone(name, outFile.getAbsolutePath());
        } finally {
            FileUtils.deleteQuietly(inFile);
            FileUtils.deleteQuietly(outFile);
        }
    }

    private File createZoneZipFile(Zone newZone, Zone prevZone) throws IOException {
        final File result = File.createTempFile("test-zonezip", ".zip");
        try (ZipOutputStream out = new ZipOutputStream(new FileOutputStream(result))) {
            // Write newZone
            final ZipEntry ze1 = new ZipEntry("files/new-zone-file-123");
            out.putNextEntry(ze1);
            out.write(newZone.toMasterFile().getBytes(StandardCharsets.UTF_8));
            out.closeEntry();
            
            // Write prevZone
            if (prevZone != null) {
                final ZipEntry ze2 = new ZipEntry("files/prev-zone-file-456");
                out.putNextEntry(ze2);
                out.write(prevZone.toMasterFile().getBytes(StandardCharsets.UTF_8));
                out.closeEntry();
            }
        }
        return result;
    }

    private HashSet<RRSIGRecord> getSignatures(final Zone zone) {
        final HashSet<RRSIGRecord> results = new HashSet<>();
        
        Iterator sets = zone.iterator();
        while (sets.hasNext()) {
            final RRset rrSet = (RRset) sets.next();
            final Iterator rrs = rrSet.sigs();
            while (rrs.hasNext()) {
                Record r = (Record) rrs.next();
                if (r instanceof RRSIGRecord) {
                    final RRSIGRecord sig = (RRSIGRecord) r;

                    results.add(sig);
                }
            }

        }
        return results;
    }

    private void assertVerifies(final String zone, final int expectedVerified, final int expectedAlgorithm) throws IOException {
        final Master master = new Master(new ByteArrayInputStream(zone.getBytes(StandardCharsets.UTF_8)));
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

    private void assertComplianceTest(Name name, String zone, long fakeTime) throws IOException {
        File signedFile = File.createTempFile("test-signed", ".zone");
        try {
            FileUtils.write(signedFile, zone, StandardCharsets.UTF_8);
            ProcResult res = ComplianceTestUtils.execute("faketime", "-f", "@" + FDF.format(fakeTime), dnssecVerifyCommand, "-v", "9",
                    "-o", name.toString(), signedFile.getAbsolutePath());
            final String output = ComplianceTestUtils.toString(res.getOutput());
            final String error = res.getErrorMessage();

            LOG.info("Result:\n" + output);
            LOG.info("Errors:\n" + error);
            assertEquals("result", 0, res.getExitValue());
            assertTrue("Expecting successful verification: " + error, error.contains("Zone fully signed"));
        } finally {
            FileUtils.deleteQuietly(signedFile);
        }
    }

    private static String toString(HashSet<RRSIGRecord> set) {
        final StringBuilder sb = new StringBuilder();
        sb.append("Set{\n");
        for (RRSIGRecord sig : set) {
            sb.append(sig).append("\n");
        }
        sb.append("\n}");
        return sb.toString();
    }
    
}
