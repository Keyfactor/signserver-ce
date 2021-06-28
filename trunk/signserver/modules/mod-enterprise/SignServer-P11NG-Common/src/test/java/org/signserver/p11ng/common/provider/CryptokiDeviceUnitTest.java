/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.p11ng.common.provider;

import java.util.Arrays;
import java.util.Collection;
import javax.security.auth.x500.X500Principal;
import junit.framework.TestCase;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.apache.log4j.Logger;
import org.junit.Test;
import org.pkcs11.jacknji11.CKA;

/**
 * Unit tests for cache interface in CryptokiDevice.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
@RunWith(Parameterized.class)
public class CryptokiDeviceUnitTest extends TestCase {
    // Logger for this class
    private static final Logger LOG = Logger.getLogger(CryptokiDeviceUnitTest.class);
    
    private final CryptokiDevice device;
    private final MockCEi c;
    private final boolean useCache;
    
    // use a dummy slot list
    private static final long[] SLOT_LIST = { 0, 1, 2 };
    
    public CryptokiDeviceUnitTest(final boolean useCache, final String title) {
        c = new MockCEi(SLOT_LIST);
        device = new CryptokiDevice(c, new JackNJI11Provider());
        device.getSlot(0L).setUseCache(useCache);
        this.useCache = useCache;
    }
    
    @Parameters(name = "{1}")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[] { true, "Using cache" },
                             new Object[] { false, "Not using cache"});
    }
    
    /**
     * Test checking that caching of findCertificateObjectsByLabel is
     * using cache when expected.
     * 
     * @throws Exception 
     */
    @Test
    public void findCertificateObjectsByLabelTest() throws Exception {
        final int findObjectsCallsBefore = c.findObjectsCalls;
        final long[] resultFirst = device.getSlot(0L).findCertificateObjectsByLabel(0L, "some_alias");
        final int findObjectsCallsAfterFirst = c.findObjectsCalls;
        
        // check that when no prior call was made with the same params
        // the Cryptoki method was called once
        assertEquals("One call to findCertificateObjectsByLabel made",
                     findObjectsCallsAfterFirst, findObjectsCallsBefore + 1);
        
        final long[] resultSecond = device.getSlot(0L).findCertificateObjectsByLabel(0L, "some_alias");
        final int findObjectsCallsAfterSecond = c.findObjectsCalls;
        
        // check that one additional call was done when not caching
        // and none when caching
        assertEquals("Calls made after second interface call",
                     findObjectsCallsAfterSecond,
                     useCache ? findObjectsCallsAfterFirst :
                                findObjectsCallsAfterFirst + 1);
        // check that the find objects result is the same
        assertTrue("Result of both calls should be equal",
                   Arrays.equals(resultFirst, resultSecond));
        
        // make an additional call with a different parameter
        final long[] resultThird = device.getSlot(0L).findCertificateObjectsByLabel(0L, "some_other_alias");
        final int findObjectsCallsAfterThird = c.findObjectsCalls;
        
        // check that one additional call was done when querying for a different
        // object
        assertEquals("Calls made after third interface call",
                     findObjectsCallsAfterThird,
                     findObjectsCallsAfterSecond + 1);
        // check that the find objects result is not the same
        assertFalse("Result of both calls should not be equal",
                   Arrays.equals(resultSecond, resultThird));
    }
    
    /**
     * Test checking that caching of findCertificateObjectsBySubject is
     * using cache when expected.
     * 
     * @throws Exception 
     */
    @Test
    public void findCertificateObjectsBySubjectTest() throws Exception {
        final int findObjectsCallsBefore = c.findObjectsCalls;
        
        final X500Principal principal1 = new X500Principal("CN=test1");
        final X500Principal principal2 = new X500Principal("CN=test2");
        
        final long[] resultFirst = device.getSlot(0L).findCertificateObjectsBySubject(0L, principal1.getEncoded());
        final int findObjectsCallsAfterFirst = c.findObjectsCalls;
        
        // check that when no prior call was made with the same params
        // the Cryptoki method was called once
        assertEquals("One call to findCertificateObjectsBySubject made",
                     findObjectsCallsAfterFirst, findObjectsCallsBefore + 1);
        
        final long[] resultSecond = device.getSlot(0L).findCertificateObjectsBySubject(0L, principal1.getEncoded());
        final int findObjectsCallsAfterSecond = c.findObjectsCalls;
        
        // check that one additional call was done when not caching
        // and none when caching
        assertEquals("Calls made after second interface call",
                     findObjectsCallsAfterSecond,
                     useCache ? findObjectsCallsAfterFirst :
                                findObjectsCallsAfterFirst + 1);
        // check that the find objects result is the same
        assertTrue("Result of both calls should be equal",
                   Arrays.equals(resultFirst, resultSecond));
        
        // make an additional call with a different parameter
        final long[] resultThird = device.getSlot(0L).findCertificateObjectsBySubject(0L, principal2.getEncoded());
        final int findObjectsCallsAfterThird = c.findObjectsCalls;
        
        // check that one additional call was done when a different call was
        // made, regardless of caching
        assertEquals("Calls made after third interface call",
                     findObjectsCallsAfterThird,
                     findObjectsCallsAfterSecond + 1);
        // check that the find objects result is not the same
        assertFalse("Result of both calls should not be equal",
                   Arrays.equals(resultSecond, resultThird));
    }
    
    /**
     * Test checking that caching of findPrivateKeyObjectsByID is
     * using cache when expected.
     * 
     * @throws Exception 
     */
    @Test
    public void findPrivateKeyObjectsByIDTest() throws Exception {
        final int findObjectsCallsBefore = c.findObjectsCalls;
        
        final byte[] dummyID1 = { 0x13, 0x37 };
        final byte[] dummyID2 = { 0x47, 0x11 };
        
        final long[] resultFirst = device.getSlot(0L).findPrivateKeyObjectsByID(0L, dummyID1);
        final int findPrivateKeyCallsAfterFirst = c.findObjectsCalls;
        
        // check that when no prior call was made with the same params
        // the Cryptoki method was called once
        assertEquals("One call to findPrivateKeyObjectsByID made",
                     findPrivateKeyCallsAfterFirst, findObjectsCallsBefore + 1);
        
        final long[] resultSecond = device.getSlot(0L).findPrivateKeyObjectsByID(0L, dummyID1);
        final int findPrivateKeyCallsAfterSecond = c.findObjectsCalls;
        
        // check that one additional call was done when not caching
        // and none when caching
        assertEquals("Calls made after second interface call",
                     findPrivateKeyCallsAfterSecond,
                     useCache ? findPrivateKeyCallsAfterFirst :
                                findPrivateKeyCallsAfterFirst + 1);
        // check that the find objects result is the same
        assertTrue("Result of both calls should be equal",
                   Arrays.equals(resultFirst, resultSecond));
        
        // make an additional call with a different parameter
        final long[] resultThird = device.getSlot(0L).findPrivateKeyObjectsByID(0L, dummyID2);
        final int findPrivateKeyCallsAfterThird = c.findObjectsCalls;
        
        // check that one additional call was done when a different call was
        // made, regardless of caching
        assertEquals("Calls made after third interface call",
                     findPrivateKeyCallsAfterThird,
                     findPrivateKeyCallsAfterSecond + 1);
        // check that the find objects result is not the same
        assertFalse("Result of both calls should not be equal",
                   Arrays.equals(resultSecond, resultThird));
    }
    
    /**
     * Test checking that caching of findSecretKeyObjectsByLabel is
     * using cache when expected.
     * 
     * @throws Exception 
     */
    @Test
    public void findSecretKeyObjectsByLabelTest() throws Exception {
        final int findSecretKeyCallsBefore = c.findObjectsCalls;
        final long[] resultFirst = device.getSlot(0L).findSecretKeyObjectsByLabel(0L, "some_alias");
        final int findSecretKeyCallsAfterFirst = c.findObjectsCalls;
        
        // check that when no prior call was made with the same params
        // the Cryptoki method was called once
        assertEquals("One call to findSecretKeyObjectsByLabel made",
                     findSecretKeyCallsAfterFirst, findSecretKeyCallsBefore + 1);
        
        final long[] resultSecond = device.getSlot(0L).findSecretKeyObjectsByLabel(0L, "some_alias");
        final int findSecretKeyCallsAfterSecond = c.findObjectsCalls;
        
        // check that one additional call was done when not caching
        // and none when caching
        assertEquals("Calls made after second interface call",
                     findSecretKeyCallsAfterSecond,
                     useCache ? findSecretKeyCallsAfterFirst :
                                findSecretKeyCallsAfterFirst + 1);
        // check that the find objects result is the same
        assertTrue("Result of both calls should be equal",
                   Arrays.equals(resultFirst, resultSecond));
        
        // make an additional call with a different parameter
        final long[] resultThird = device.getSlot(0L).findSecretKeyObjectsByLabel(0L, "some_other_alias");
        final int findSecretKeyCallsAfterThird = c.findObjectsCalls;
        
        // check that one additional call was done when a different call was
        // made, regardless of caching
        assertEquals("Calls made after third interface call",
                     findSecretKeyCallsAfterThird,
                     findSecretKeyCallsAfterSecond + 1);
        // check that the find objects result is not the same
        assertFalse("Result of both calls should not be equal",
                   Arrays.equals(resultSecond, resultThird));
    }
    
    /**
     * Test checking that caching of getAttributeCertificateID is
     * using cache when expected.
     * 
     * @throws Exception 
     */
    @Test
    public void getAttributeCertificateIDTest() throws Exception {
        final int findACCallsBefore = c.getAttributeValueCalls;
        final long id1 = 4711;
        final long id2 = 1337;
        final CKA resultFirst = device.getSlot(0L).getAttributeCertificateID(0L, id1);
        final int getACCallsAfterFirst = c.getAttributeValueCalls;
        
        // check that when no prior call was made with the same params
        // the Cryptoki method was called once
        assertEquals("One call to getAttributeCertificateID made",
                     getACCallsAfterFirst, findACCallsBefore + 1);
        
        final CKA resultSecond = device.getSlot(0L).getAttributeCertificateID(0L, id1);
        final int getACCallsAfterSecond = c.getAttributeValueCalls;
        
        // check that one additional call was done when not caching
        // and none when caching
        assertEquals("Calls made after second interface call",
                     getACCallsAfterSecond,
                     useCache ? getACCallsAfterFirst :
                                getACCallsAfterFirst + 1);
        // check that the get attributes result is the same
        assertTrue("Result of both calls should be equal",
                   Arrays.equals(resultFirst.getValue(), resultSecond.getValue()));
        
        // make an additional call with a different parameter
        final CKA resultThird = device.getSlot(0L).getAttributeCertificateID(0L, id2);
        final int getACCallsAfterThird = c.getAttributeValueCalls;
        
        // check that one additional call was done when a different call was
        // made, regardless of caching
        assertEquals("Calls made after third interface call",
                     getACCallsAfterThird,
                     getACCallsAfterSecond + 1);
        // check that the find objects result is not the same
        assertFalse("Result of both calls should not be equal",
                   Arrays.equals(resultSecond.getValue(), resultThird.getValue()));
    }
    
    /**
     * Test checking that caching of getAttributeCertificateValue is
     * using cache when expected.
     * 
     * @throws Exception 
     */
    @Test
    public void getAttributeCertificateValueTest() throws Exception {
        final int findACCallsBefore = c.getAttributeValueCalls;
        final long id1 = 4711;
        final long id2 = 1337;
        final CKA resultFirst = device.getSlot(0L).getAttributeCertificateValue(0L, id1);
        final int getACCallsAfterFirst = c.getAttributeValueCalls;
        
        // check that when no prior call was made with the same params
        // the Cryptoki method was called once
        assertEquals("One call to getAttributeCertificateValue made",
                     getACCallsAfterFirst, findACCallsBefore + 1);
        
        final CKA resultSecond = device.getSlot(0L).getAttributeCertificateValue(0L, id1);
        final int getACCallsAfterSecond = c.getAttributeValueCalls;
        
        // check that one additional call was done when not caching
        // and none when caching
        assertEquals("Calls made after second interface call",
                     getACCallsAfterSecond,
                     useCache ? getACCallsAfterFirst :
                                getACCallsAfterFirst + 1);
        // check that the get attributes result is the same
        assertTrue("Result of both calls should be equal",
                   Arrays.equals(resultFirst.getValue(), resultSecond.getValue()));
        
        // make an additional call with a different parameter
        final CKA resultThird = device.getSlot(0L).getAttributeCertificateValue(0L, id2);
        final int getACCallsAfterThird = c.getAttributeValueCalls;
        
        // check that one additional call was done when a different call was
        // made, regardless of caching
        assertEquals("Calls made after third interface call",
                     getACCallsAfterThird,
                     getACCallsAfterSecond + 1);
        // check that the get attributes result is not the same
        assertFalse("Result of both calls should not be equal",
                   Arrays.equals(resultSecond.getValue(), resultThird.getValue()));
    }
    
    /**
     * Test checking that there is no caching of getUnwrappedPrivateKey.
     *
     * @throws Exception
     */
    @Test
    public void getUnwrappedPrivateKeyTest() throws Exception {
        final int unwrapKeyCallsBefore = c.unwrapKeyCalls;

        CKA[] dummyUnwrappedPrivateKeyTemplate = new CKA[]{};
        final byte[] wrappedPrivateKey = {0x13, 0x37};
        final long dummyWrappingCipher = 4711;
        final long dummyUnWrapKey1 = 1337;
        final long dummyUnWrapKey2 = 1338;
        final long resultFirst = device.getSlot(0L).getUnwrappedPrivateKey(0L, dummyWrappingCipher, dummyUnWrapKey1, wrappedPrivateKey, dummyUnwrappedPrivateKeyTemplate);
        final int unwrapKeyCallsAfterFirst = c.unwrapKeyCalls;

        // check that when no prior call was made with the same params
        // the Cryptoki method was called once
        assertEquals("One call to getUnwrappedPrivateKey made",
                unwrapKeyCallsAfterFirst, unwrapKeyCallsBefore + 1);

        final long resultSecond = device.getSlot(0L).getUnwrappedPrivateKey(0L, dummyWrappingCipher, dummyUnWrapKey1, wrappedPrivateKey, dummyUnwrappedPrivateKeyTemplate);
        final int unwrapKeyCallsAfterSecond = c.unwrapKeyCalls;

        // check that one additional call was done (= no caching of the key should be made)
        assertEquals("Calls made after second interface call",
                unwrapKeyCallsAfterSecond,
                unwrapKeyCallsAfterFirst + 1);
        // check that the getUnwrappedPrivateKey result is the same
        assertTrue("Result of both calls should be equal", resultFirst == resultSecond);

        // make an additional call with a different parameter
        final long resultThird = device.getSlot(0L).getUnwrappedPrivateKey(0L, dummyWrappingCipher, dummyUnWrapKey2, wrappedPrivateKey, dummyUnwrappedPrivateKeyTemplate);
        final int unwrapKeyCallsAfterThird = c.unwrapKeyCalls;

        // check that one additional call was done when a different call was
        // made, regardless of caching
        assertEquals("Calls made after third interface call",
                unwrapKeyCallsAfterThird,
                unwrapKeyCallsAfterSecond + 1);
        // check that the get attributes result is not the same
        assertFalse("Result of both calls should not be equal", resultSecond == resultThird);
    }
    
    /**
     * Test that calling findCertificateObjectsByLabel with the same parameters
     * using different slots will always result in a call to the underlying
     * interface regardless of caching.
     * 
     * @throws Exception 
     */
    @Test
    public void findCertificateObjectsByLabelDifferentSlotsTest() throws Exception {
        final int findObjectsCallsBefore = c.findObjectsCalls;
        device.getSlot(0L).findCertificateObjectsByLabel(0L, "some_alias");
        final int findObjectsCallsAfterFirst = c.findObjectsCalls;
        
        // check that when no prior call was made with the same params
        // the Cryptoki method was called once
        assertEquals("One call to findCertificateObjectsByLabel made",
                     findObjectsCallsAfterFirst, findObjectsCallsBefore + 1);
        
        device.getSlot(1L).findCertificateObjectsByLabel(0L, "some_alias");
        final int findObjectsCallsAfterSecond = c.findObjectsCalls;
        
        // check that one additional call was done both when running
        // with and without cache, as it's different slots
        assertEquals("Calls made after second interface call",
                     findObjectsCallsAfterSecond, findObjectsCallsAfterFirst + 1);
    }
    
    /**
     * Test that calling findCertificateObjectsBySubject with the same parameters
     * using different slots will always result in a call to the underlying
     * interface regardless of caching.
     * 
     * @throws Exception 
     */
    @Test
    public void findCertificateObjectsBySubjectDifferentSlotsTest() throws Exception {
        final X500Principal principal = new X500Principal("CN=test1");
        final int findCOCallsBefore = c.findObjectsCalls;
        device.getSlot(0L).findCertificateObjectsBySubject(0L, principal.getEncoded());
        final int findCOCallsAfterFirst = c.findObjectsCalls;
        
        // check that when no prior call was made with the same params
        // the Cryptoki method was called once
        assertEquals("One call to findCertificateObjectsBySubject made",
                     findCOCallsAfterFirst, findCOCallsBefore + 1);
        
        device.getSlot(1L).findCertificateObjectsBySubject(0L, principal.getEncoded());
        final int findCOCallsAfterSecond = c.findObjectsCalls;
        
        // check that one additional call was done both when running
        // with and without cache, as it's different slots
        assertEquals("Calls made after second interface call",
                     findCOCallsAfterSecond, findCOCallsAfterFirst + 1);
    }
    
    /**
     * Test that calling findPrivateKeyObjectsByID with the same parameters
     * using different slots will always result in a call to the underlying
     * interface regardless of caching.
     * 
     * @throws Exception 
     */
    @Test
    public void findPrivateKeyObjectsByIDDifferentSlotsTest() throws Exception {
        final int findPKOCallsBefore = c.findObjectsCalls;
        
        final byte[] dummyID1 = { 0x13, 0x37 };
        
        device.getSlot(0L).findPrivateKeyObjectsByID(0L, dummyID1);
        final int findPKOCallsAfterFirst = c.findObjectsCalls;
        
        // check that when no prior call was made with the same params
        // the Cryptoki method was called once
        assertEquals("One call to findPrivateKeyObjectsByID made",
                     findPKOCallsAfterFirst, findPKOCallsBefore + 1);
        
        device.getSlot(1L).findPrivateKeyObjectsByID(0L, dummyID1);
        final int findPKOCallsAfterSecond = c.findObjectsCalls;
        
        // check that one additional call was done both when running
        // with and without cache, as it's different slots
        assertEquals("Calls made after second interface call",
                     findPKOCallsAfterSecond,
                     findPKOCallsAfterFirst + 1);
    }
    
    /**
     * Test that calling getAttributeCertificateID with the same parameters
     * using different slots will always result in a call to the underlying
     * interface regardless of caching.
     * 
     * @throws Exception 
     */
    @Test
    public void getAttributeCertificateIDDifferentSlotsTest() throws Exception {
        final int findACCallsBefore = c.getAttributeValueCalls;
        final long id1 = 4711;
        device.getSlot(0L).getAttributeCertificateID(0L, id1);
        final int findACCallsAfterFirst = c.getAttributeValueCalls;
        
        // check that when no prior call was made with the same params
        // the Cryptoki method was called once
        assertEquals("One call to getAttributeCertificateID made",
                     findACCallsAfterFirst, findACCallsBefore + 1);
        
        device.getSlot(1L).getAttributeCertificateID(0L, id1);
        final int findACCallsAfterSecond = c.getAttributeValueCalls;

        // check that one additional call was done both when running
        // with and without cache, as it's different slots
        assertEquals("Calls made after second interface call",
                     findACCallsAfterSecond, findACCallsAfterFirst + 1);
    }
    
    /**
     * Test that calling getAttributeCertificateValue with the same parameters
     * using different slots will always result in a call to the underlying
     * interface regardless of caching.
     * 
     * @throws Exception 
     */
    @Test
    public void getAttributeCertificateValueDifferentSlotsTest() throws Exception {
        final int findACCallsBefore = c.getAttributeValueCalls;
        final long id1 = 4711;
        device.getSlot(0L).getAttributeCertificateValue(0L, id1);
        final int findACCallsAfterFirst = c.getAttributeValueCalls;
        
        // check that when no prior call was made with the same params
        // the Cryptoki method was called once
        assertEquals("One call to getAttributeCertificateValue made",
                     findACCallsAfterFirst, findACCallsBefore + 1);
        
        device.getSlot(1L).getAttributeCertificateValue(0L, id1);
        final int findACCallsAfterSecond = c.getAttributeValueCalls;

        // check that one additional call was done both when running
        // with and without cache, as it's different slots
        assertEquals("Calls made after second interface call",
                     findACCallsAfterSecond, findACCallsAfterFirst + 1);
    }
    
    /**
     * Test that calling getUnwrappedPrivateKey with the same parameters
     * using different slots will always result in a call to the underlying
     * interface regardless of caching.
     * 
     * @throws Exception 
     */
    @Test
    public void getUnwrappedPrivateKeyDifferentSlotsTest() throws Exception {
        final int unwrapKeyCallsBefore = c.unwrapKeyCalls;
        CKA[] dummyUnwrappedPrivateKeyTemplate = new CKA[]{};
        final byte[] wrappedPrivateKey = {0x13, 0x37};
        final long dummyWrappingCipher = 4711;
        final long dummyUnWrapKey = 1337;        
        device.getSlot(0L).getUnwrappedPrivateKey(0L, dummyWrappingCipher, dummyUnWrapKey, wrappedPrivateKey, dummyUnwrappedPrivateKeyTemplate);
        final int unwrapKeyCallsAfterFirst = c.unwrapKeyCalls;
        
        // check that when no prior call was made with the same params
        // the Cryptoki method was called once
        assertEquals("One call to getUnwrappedPrivateKey made",
                     unwrapKeyCallsAfterFirst, unwrapKeyCallsBefore + 1);
        
        device.getSlot(1L).getUnwrappedPrivateKey(0L, dummyWrappingCipher, dummyUnWrapKey, wrappedPrivateKey, dummyUnwrappedPrivateKeyTemplate);
        final int unwrapKeyCallsAfterSecond = c.unwrapKeyCalls;

        // check that one additional call was done both when running
        // with and without cache, as it's different slots
        assertEquals("Calls made after second interface call",
                     unwrapKeyCallsAfterSecond, unwrapKeyCallsAfterFirst + 1);
    }
    
    /**
     * Test that removing private key clears cached results and subsequent calls
     * to findPrivateKeyObjectsByID method will always result in a call to the
     * underlying interface regardless of caching.
     *
     * @throws Exception
     */
    @Test
    public void removePrivateKeyObjectTest() throws Exception {
        final int findObjectsCallsAtStart = c.findObjectsCalls;
        final byte[] dummyID = {0x47, 0x11};
        final long[] resultBeforeKeyRemoval1 = device.getSlot(0L).findPrivateKeyObjectsByID(0L, dummyID);
        final int findObjectsCallsBeforeKeyRemoval1 = c.findObjectsCalls;

        // check that when no prior call was made with the same params
        // the Cryptoki method was called once
        assertEquals("One call to findPrivateKeyObjectsByID made", findObjectsCallsBeforeKeyRemoval1, findObjectsCallsAtStart + 1);

        final long[] resultBeforeKeyRemoval2 = device.getSlot(0L).findPrivateKeyObjectsByID(0L, dummyID);
        final int findObjectsCallsBeforeKeyRemoval2 = c.findObjectsCalls;
        // check that one additional call was done when not caching and none when caching
        assertEquals("Calls made to findPrivateKeyObjectsByID method", findObjectsCallsBeforeKeyRemoval2, useCache ? findObjectsCallsBeforeKeyRemoval1
                : findObjectsCallsBeforeKeyRemoval1 + 1);
        // check that the find objects result is the same 
        assertTrue("Result of both calls should be equal", Arrays.equals(resultBeforeKeyRemoval1, resultBeforeKeyRemoval2));
        assertEquals("No of found objects", 1, resultBeforeKeyRemoval1.length);

        // Now remove the key object
        device.getSlot(0L).removeKeyObject(0L, resultBeforeKeyRemoval1[0]);
        // Check that additional call was made as cache should have been invalidated now
        final long[] resultAfterKeyRemoval = device.getSlot(0L).findPrivateKeyObjectsByID(0L, dummyID);
        final int findObjectsCallsAfterKeyRemoval = c.findObjectsCalls;
        assertEquals("One call to findPrivateKeyObjectsByID made", findObjectsCallsAfterKeyRemoval, findObjectsCallsBeforeKeyRemoval2 + 1);
        assertTrue("Result of both calls should be equal", Arrays.equals(resultBeforeKeyRemoval1, resultAfterKeyRemoval));
    }
    
    /**
     * Test that removing secret key clears cached results and subsequent calls
     * to findSecretKeyObjectsByLabel method will always result in a call to the
     * underlying interface regardless of caching.
     *
     * @throws Exception
     */
    @Test
    public void removeSecretKeyObjectTest() throws Exception {
        final int findObjectsCallsAtStart = c.findObjectsCalls;        
        final long[] resultBeforeKeyRemoval1 = device.getSlot(0L).findSecretKeyObjectsByLabel(0L, "some_alias");
        final int findObjectsCallsBeforeKeyRemoval1 = c.findObjectsCalls;

        // check that when no prior call was made with the same params
        // the Cryptoki method was called once
        assertEquals("One call to findSecretKeyObjectsByLabel made", findObjectsCallsBeforeKeyRemoval1, findObjectsCallsAtStart + 1);

        final long[] resultBeforeKeyRemoval2 = device.getSlot(0L).findSecretKeyObjectsByLabel(0L, "some_alias");
        final int findObjectsCallsBeforeKeyRemoval2 = c.findObjectsCalls;
        // check that one additional call was done when not caching and none when caching
        assertEquals("Calls made to findSecretKeyObjectsByLabel method", findObjectsCallsBeforeKeyRemoval2, useCache ? findObjectsCallsBeforeKeyRemoval1
                : findObjectsCallsBeforeKeyRemoval1 + 1);
        // check that the find objects result is the same 
        assertTrue("Result of both calls should be equal", Arrays.equals(resultBeforeKeyRemoval1, resultBeforeKeyRemoval2));
        assertEquals("No of found objects", 1, resultBeforeKeyRemoval1.length);

        // Now remove the key object
        device.getSlot(0L).removeKeyObject(0L, resultBeforeKeyRemoval1[0]);
        // Check that additional call was made as cache should have been invalidated now
        final long[] resultAfterKeyRemoval = device.getSlot(0L).findSecretKeyObjectsByLabel(0L, "some_alias");
        final int findObjectsCallsAfterKeyRemoval = c.findObjectsCalls;
        assertEquals("One call to findPrivateKeyObjectsByID made", findObjectsCallsAfterKeyRemoval, findObjectsCallsBeforeKeyRemoval2 + 1);
        assertTrue("Result of both calls should be equal", Arrays.equals(resultBeforeKeyRemoval1, resultAfterKeyRemoval));
    }
    
    /**
     * Test that removing certificate object clears cached results
     * (corresponding to find objects & attribute value calls) and subsequent
     * calls to findCertificateObjectsByLabel method will always result in a
     * call to the underlying interface regardless of caching.
     *
     * @throws Exception
     */
    @Test
    public void removeCertificateObjectTest_Call_FindCertificateObjectsByLabel() throws Exception {
        final int findObjectsCallsAtStart = c.findObjectsCalls;
        final int findACCallsAtStart = c.getAttributeValueCalls;

        final long[] resultBeforeCertRemoval1 = device.getSlot(0L).findCertificateObjectsByLabel(0L, "some_alias");
        final int findObjectsCallsBeforeCertRemoval1 = c.findObjectsCalls;
        assertEquals("No of found objects", 1, resultBeforeCertRemoval1.length);
        device.getSlot(0L).getAttributeCertificateID(0L, resultBeforeCertRemoval1[0]);
        device.getSlot(0L).getAttributeCertificateValue(0L, resultBeforeCertRemoval1[0]);
        final int findACCallsBeforeCertRemoval1 = c.getAttributeValueCalls;

        // check that when no prior call was made with the same params the Cryptoki method was called as mentioned times
        assertEquals("One call to findCertificateObjectsByLabel made", findObjectsCallsBeforeCertRemoval1, findObjectsCallsAtStart + 1);
        assertEquals("Two calls to GetAttributeValue made", findACCallsBeforeCertRemoval1, findACCallsAtStart + 2);

        final long[] resultBeforeCertRemoval2 = device.getSlot(0L).findCertificateObjectsByLabel(0L, "some_alias");
        final int findObjectsCallsBeforeCertRemoval2 = c.findObjectsCalls;
        device.getSlot(0L).getAttributeCertificateID(0L, resultBeforeCertRemoval1[0]);
        device.getSlot(0L).getAttributeCertificateValue(0L, resultBeforeCertRemoval1[0]);
        final int findACCallsBeforeCertRemoval2 = c.getAttributeValueCalls;

        // check that additional call was done when not caching and none when caching
        assertTrue("Result of both calls should be equal", Arrays.equals(resultBeforeCertRemoval1, resultBeforeCertRemoval2));
        assertEquals("Calls to findCertificateObjectsByLabel", findObjectsCallsBeforeCertRemoval2, useCache ? findObjectsCallsBeforeCertRemoval1
                : findObjectsCallsBeforeCertRemoval1 + 1);
        assertEquals("Calls to GetAttributeValue", findACCallsBeforeCertRemoval2, useCache ? findACCallsBeforeCertRemoval1
                : findACCallsBeforeCertRemoval1 + 2);

        // Remove the certificate object now     
        device.getSlot(0L).removeCertificateObject(0L, resultBeforeCertRemoval1[0]);

        // Check that additional call were made as mentioned times since cache should have been invalidated now
        device.getSlot(0L).findCertificateObjectsByLabel(0L, "some_alias");
        final int findObjectsCallsAfterCertRemoval = c.findObjectsCalls;
        device.getSlot(0L).getAttributeCertificateID(0L, resultBeforeCertRemoval1[0]);
        device.getSlot(0L).getAttributeCertificateValue(0L, resultBeforeCertRemoval1[0]);
        final int findACCallsAfterCertRemoval = c.getAttributeValueCalls;

        assertEquals("One call to findCertificateObjectsByLabel made", findObjectsCallsAfterCertRemoval, findObjectsCallsBeforeCertRemoval2 + 1);
        assertEquals("Two calls to GetAttributeValue made", findACCallsAfterCertRemoval, findACCallsBeforeCertRemoval2 + 2);
    }

    /**
     * Test that removing certificate object clears cached results (
     * corresponding to find objects & attribute value calls) and subsequent
     * calls to findCertificateObjectsBySubject method will always result in a
     * call to the underlying interface regardless of caching.
     *
     * @throws Exception
     */
    @Test
    public void removeCertificateObjectTest_Call_FindCertificateObjectsBySubject() throws Exception {
        final int findObjectsCallsAtStart = c.findObjectsCalls;
        final int findACCallsAtStart = c.getAttributeValueCalls;

        final X500Principal principal = new X500Principal("CN=test1");
        final long[] resultBeforeCertRemoval1 = device.getSlot(0L).findCertificateObjectsBySubject(0L, principal.getEncoded());
        final int findObjectsCallsBeforeCertRemoval1 = c.findObjectsCalls;
        assertEquals("No of found objects", 1, resultBeforeCertRemoval1.length);
        device.getSlot(0L).getAttributeCertificateID(0L, resultBeforeCertRemoval1[0]);
        device.getSlot(0L).getAttributeCertificateValue(0L, resultBeforeCertRemoval1[0]);
        final int findACCallsBeforeCertRemoval1 = c.getAttributeValueCalls;

        // check that when no prior call was made with the same params the Cryptoki method was called as mentioned times
        assertEquals("One call to findCertificateObjectsBySubject made", findObjectsCallsBeforeCertRemoval1, findObjectsCallsAtStart + 1);
        assertEquals("Two calls to GetAttributeValue made", findACCallsBeforeCertRemoval1, findACCallsAtStart + 2);

        final long[] resultBeforeCertRemoval2 = device.getSlot(0L).findCertificateObjectsBySubject(0L, principal.getEncoded());
        final int findObjectsCallsBeforeCertRemoval2 = c.findObjectsCalls;
        device.getSlot(0L).getAttributeCertificateID(0L, resultBeforeCertRemoval1[0]);
        device.getSlot(0L).getAttributeCertificateValue(0L, resultBeforeCertRemoval1[0]);
        final int findACCallsBeforeCertRemoval2 = c.getAttributeValueCalls;

        // check that additional call was done when not caching and none when caching
        assertTrue("Result of both calls should be equal", Arrays.equals(resultBeforeCertRemoval1, resultBeforeCertRemoval2));
        assertEquals("Calls to findCertificateObjectsBySubject", findObjectsCallsBeforeCertRemoval2, useCache ? findObjectsCallsBeforeCertRemoval1
                : findObjectsCallsBeforeCertRemoval1 + 1);
        assertEquals("Calls to GetAttributeValue", findACCallsBeforeCertRemoval2, useCache ? findACCallsBeforeCertRemoval1
                : findACCallsBeforeCertRemoval1 + 2);

        // Remove the certificate object now     
        device.getSlot(0L).removeCertificateObject(0L, resultBeforeCertRemoval1[0]);

        // Check that additional call were made as mentioned times since cache should have been invalidated now
        device.getSlot(0L).findCertificateObjectsBySubject(0L, principal.getEncoded());
        final int findObjectsCallsAfterCertRemoval = c.findObjectsCalls;
        device.getSlot(0L).getAttributeCertificateID(0L, resultBeforeCertRemoval1[0]);
        device.getSlot(0L).getAttributeCertificateValue(0L, resultBeforeCertRemoval1[0]);
        final int findACCallsAfterCertRemoval = c.getAttributeValueCalls;

        assertEquals("One call to findCertificateObjectsBySubject made", findObjectsCallsAfterCertRemoval, findObjectsCallsBeforeCertRemoval2 + 1);
        assertEquals("Two calls to GetAttributeValue made", findACCallsAfterCertRemoval, findACCallsBeforeCertRemoval2 + 2);
    }

}
