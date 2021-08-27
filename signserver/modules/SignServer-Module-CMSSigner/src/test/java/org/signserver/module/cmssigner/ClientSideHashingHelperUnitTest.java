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
package org.signserver.module.cmssigner;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.RequestMetadata;
import org.signserver.common.WorkerConfig;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.hamcrest.core.StringContains.containsString;
import static org.signserver.module.cmssigner.ClientSideHashingHelper.ACCEPTED_HASHDIGEST_ALGORITHMS;
import static org.signserver.module.cmssigner.ClientSideHashingHelper.ALLOW_CLIENTSIDEHASHING_OVERRIDE;
import static org.signserver.module.cmssigner.ClientSideHashingHelper.CLIENTSIDEHASHING;
import static org.signserver.module.cmssigner.ClientSideHashingHelper.CLIENTSIDE_HASHDIGESTALGORITHM_PROPERTY;
import static org.signserver.module.cmssigner.ClientSideHashingHelper.USING_CLIENTSUPPLIED_HASH_PROPERTY;

/**
 * A unit test for ClientSideHashingHelper.
 *
 * @author Andrey Sergeev
 * @version $Id$
 */
public class ClientSideHashingHelperUnitTest {

    private static final Logger LOG = Logger.getLogger(ClientSideHashingHelperUnitTest.class);

    private static final String TRUE = Boolean.TRUE.toString();
    private static final String FALSE = Boolean.FALSE.toString();

    /**
     * Important WorkerConfig properties are:
     * - CLIENTSIDEHASHING
     * - ALLOW_CLIENTSIDEHASHING_OVERRIDE
     * - ACCEPTED_HASHDIGEST_ALGORITHMS
     * - CLIENTSIDE_HASHDIGESTALGORITHM_PROPERTY
     */
    private WorkerConfig workerConfig;
    private LinkedList<String> workerConfigErrors;
    private final RequestContext requestContext = new RequestContext();
    private Map<String, String> requestMetadataMap;
    // Class under test
    private ClientSideHashingHelper helper;

    @Rule
    public ExpectedException exceptionRule = ExpectedException.none();

    @Before
    public void setUp() {
        helper = new ClientSideHashingHelper();
        workerConfig = new WorkerConfig();
        workerConfigErrors = new LinkedList<>();
        requestMetadataMap = new HashMap<>();
    }

    /**
     * We test shouldUseClientSideHashing(...) method body, if:
     * - CLIENTSIDEHASHING = false;
     * - ALLOW_CLIENTSIDEHASHING_OVERRIDE = false;
     * - USING_CLIENTSUPPLIED_HASH_PROPERTY unset.
     * should return false.
     */
    @Test
    public void usingClientSuppliedHashRequestUnset() throws Exception {
        // given
        workerConfig.setProperty(CLIENTSIDEHASHING, FALSE);
        workerConfig.setProperty(ALLOW_CLIENTSIDEHASHING_OVERRIDE, FALSE);
        workerConfig.setProperty(ACCEPTED_HASHDIGEST_ALGORITHMS, "");
        helper.init(workerConfig, workerConfigErrors);
        // when
        final boolean result = helper.shouldUseClientSideHashing(requestContext);
        LOG.info("usingClientSuppliedHashUnset:" + result);
        // then
        assertFalse("If 'USING_CLIENTSUPPLIED_HASH' unset, should return false.", result);
        assertEquals("Should not have errors", Collections.EMPTY_LIST, workerConfigErrors);
    }

    /**
     * We test shouldUseClientSideHashing(...) method body, if:
     * - CLIENTSIDEHASHING = false;
     * - ALLOW_CLIENTSIDEHASHING_OVERRIDE = false;
     * - USING_CLIENTSUPPLIED_HASH_PROPERTY = false.
     * should return false.
     */
    @Test
    public void usingClientSuppliedHashRequestSetToFalse() throws Exception {
        // given
        workerConfig.setProperty(CLIENTSIDEHASHING, FALSE);
        workerConfig.setProperty(ALLOW_CLIENTSIDEHASHING_OVERRIDE, FALSE);
        workerConfig.setProperty(ACCEPTED_HASHDIGEST_ALGORITHMS, "");
        helper.init(workerConfig, workerConfigErrors);
        requestMetadataMap.put(USING_CLIENTSUPPLIED_HASH_PROPERTY, FALSE);
        RequestMetadata.getInstance(requestContext).putAll(requestMetadataMap);
        // when
        final boolean result = helper.shouldUseClientSideHashing(requestContext);
        // then
        assertFalse("If 'USING_CLIENTSUPPLIED_HASH' set to false, should return false.", result);
        assertEquals("Should not have errors", Collections.EMPTY_LIST, workerConfigErrors);
    }

    /**
     * We test shouldUseClientSideHashing(...) method body, if:
     * - CLIENTSIDEHASHING = false;
     * - ALLOW_CLIENTSIDEHASHING_OVERRIDE = false;
     * - USING_CLIENTSUPPLIED_HASH_PROPERTY true.
     * should throw IllegalRequestException because of CLIENTSIDEHASHING and ALLOW_CLIENTSIDEHASHING_OVERRIDE.
     */
    @Test
    public void failureClientSuppliedHashRequestSetToTrue() throws Exception {
        // given
        workerConfig.setProperty(CLIENTSIDEHASHING, FALSE);
        workerConfig.setProperty(ALLOW_CLIENTSIDEHASHING_OVERRIDE, FALSE);
        workerConfig.setProperty(ACCEPTED_HASHDIGEST_ALGORITHMS, "");
        helper.init(workerConfig, workerConfigErrors);
        requestMetadataMap.put(USING_CLIENTSUPPLIED_HASH_PROPERTY, TRUE);
        RequestMetadata.getInstance(requestContext).putAll(requestMetadataMap);
        // then
        exceptionRule.expect(IllegalRequestException.class);
        exceptionRule.expectMessage("Client-side hashing requested but not allowed");
        // when
        helper.shouldUseClientSideHashing(requestContext);
    }

    /**
     * We test shouldUseClientSideHashing(...) method body, if:
     * - CLIENTSIDEHASHING = true;
     * - ALLOW_CLIENTSIDEHASHING_OVERRIDE = false;
     * - USING_CLIENTSUPPLIED_HASH_PROPERTY false.
     * should throw IllegalRequestException because of CLIENTSIDEHASHING and ALLOW_CLIENTSIDEHASHING_OVERRIDE.
     */
    @Test
    public void failureClientSuppliedHashSetToFalse() throws Exception {
        // given
        workerConfig.setProperty(CLIENTSIDEHASHING, TRUE);
        workerConfig.setProperty(ALLOW_CLIENTSIDEHASHING_OVERRIDE, FALSE);
        workerConfig.setProperty(ACCEPTED_HASHDIGEST_ALGORITHMS, "");
        helper.init(workerConfig, workerConfigErrors);
        requestMetadataMap.put(USING_CLIENTSUPPLIED_HASH_PROPERTY, FALSE);
        RequestMetadata.getInstance(requestContext).putAll(requestMetadataMap);
        // then
        exceptionRule.expect(IllegalRequestException.class);
        exceptionRule.expectMessage("Server-side hashing requested but not allowed");
        // when
        helper.shouldUseClientSideHashing(requestContext);
    }

    /**
     * We test shouldUseClientSideHashing(...) method body, if:
     * - CLIENTSIDEHASHING = true;
     * - ALLOW_CLIENTSIDEHASHING_OVERRIDE = true;
     * - USING_CLIENTSUPPLIED_HASH_PROPERTY = true.
     * should return true, but with error due to ACCEPTED_HASHDIGEST_ALGORITHMS.
     */
    @Test
    public void usingClientSuppliedHashSetToTrueAcceptedButErrors() throws Exception {
        // given
        workerConfig.setProperty(CLIENTSIDEHASHING, TRUE);
        workerConfig.setProperty(ALLOW_CLIENTSIDEHASHING_OVERRIDE, TRUE);
        workerConfig.setProperty(ACCEPTED_HASHDIGEST_ALGORITHMS, "");
        helper.init(workerConfig, workerConfigErrors);
        requestMetadataMap.put(USING_CLIENTSUPPLIED_HASH_PROPERTY, TRUE);
        RequestMetadata.getInstance(requestContext).putAll(requestMetadataMap);
        // when
        final boolean result = helper.shouldUseClientSideHashing(requestContext);
        // then
        assertTrue("If 'USING_CLIENTSUPPLIED_HASH' set to true, should return true.", result);
        assertNotEquals("Should have errors'", Collections.EMPTY_LIST, workerConfigErrors);
        final String errorMessage = workerConfigErrors.getFirst();
        assertThat(
                "Should have an error about missing 'ACCEPTED_HASH_DIGEST_ALGORITHMS'",
                errorMessage,
                containsString("Must specify ACCEPTED_HASH_DIGEST_ALGORITHMS when")
        );
    }

    /**
     * We test shouldUseClientSideHashing(...) method body, if:
     * - CLIENTSIDEHASHING = true;
     * - ALLOW_CLIENTSIDEHASHING_OVERRIDE = true;
     * - USING_CLIENTSUPPLIED_HASH_PROPERTY = true.
     * should return true.
     */
    @Test
    public void usingClientSuppliedHashSetToTrueAccepted() throws Exception {
        // given
        workerConfig.setProperty(CLIENTSIDEHASHING, TRUE);
        workerConfig.setProperty(ALLOW_CLIENTSIDEHASHING_OVERRIDE, TRUE);
        workerConfig.setProperty(ACCEPTED_HASHDIGEST_ALGORITHMS, "SHA-256,SHA-512");
        helper.init(workerConfig, workerConfigErrors);
        requestMetadataMap.put(USING_CLIENTSUPPLIED_HASH_PROPERTY, TRUE);
        RequestMetadata.getInstance(requestContext).putAll(requestMetadataMap);
        // when
        final boolean result = helper.shouldUseClientSideHashing(requestContext);
        // then
        assertTrue("If 'USING_CLIENTSUPPLIED_HASH' set to true, should return true.", result);
        assertEquals("Should not have errors", Collections.EMPTY_LIST, workerConfigErrors);
    }

    /**
     * We test getClientSideHashAlgorithm, if:
     * - CLIENTSIDE_HASHDIGESTALGORITHM_PROPERTY - unknown algorithm.
     * should throw IllegalRequestException because of CLIENTSIDE_HASHDIGESTALGORITHM_PROPERTY.
     */
    @Test
    public void failureOnAlgorithmIdentifierWithUnknownAlgorithm() throws Exception {
        // given
        workerConfig.setProperty(CLIENTSIDEHASHING, TRUE);
        workerConfig.setProperty(ALLOW_CLIENTSIDEHASHING_OVERRIDE, TRUE);
        workerConfig.setProperty(ACCEPTED_HASHDIGEST_ALGORITHMS, "");
        helper.init(workerConfig, workerConfigErrors);
        requestMetadataMap.put(USING_CLIENTSUPPLIED_HASH_PROPERTY, TRUE);
        requestMetadataMap.put(CLIENTSIDE_HASHDIGESTALGORITHM_PROPERTY, "XYZ");
        RequestMetadata.getInstance(requestContext).putAll(requestMetadataMap);
        // then
        exceptionRule.expect(IllegalRequestException.class);
        exceptionRule.expectMessage("Client-side hashing request must specify hash algorithm used");
        // when
        helper.getClientSideHashAlgorithm(requestContext);
    }

    /**
     * We test getClientSideHashAlgorithm, if:
     * - CLIENTSIDE_HASHDIGESTALGORITHM_PROPERTY - SHA-256;
     * - ACCEPTED_HASHDIGEST_ALGORITHMS - SHA-512.
     * should throw IllegalRequestException because of mismatch of accepted algorithms.
     */
    @Test
    public void failureOnAlgorithmIdentifierWithOtherAcceptedHashDigestAlgorithms() throws Exception {
        // given
        workerConfig.setProperty(CLIENTSIDEHASHING, TRUE);
        workerConfig.setProperty(ALLOW_CLIENTSIDEHASHING_OVERRIDE, TRUE);
        workerConfig.setProperty(ACCEPTED_HASHDIGEST_ALGORITHMS, "SHA-512");
        helper.init(workerConfig, workerConfigErrors);
        requestMetadataMap.put(USING_CLIENTSUPPLIED_HASH_PROPERTY, TRUE);
        requestMetadataMap.put(CLIENTSIDE_HASHDIGESTALGORITHM_PROPERTY, "SHA-256");
        RequestMetadata.getInstance(requestContext).putAll(requestMetadataMap);
        // then
        exceptionRule.expect(IllegalRequestException.class);
        exceptionRule.expectMessage("Client specified a non-accepted digest hash algorithm");
        // when
        helper.getClientSideHashAlgorithm(requestContext);
    }

    /**
     * We test getClientSideHashAlgorithm, if:
     * - CLIENTSIDE_HASHDIGESTALGORITHM_PROPERTY - SHA-256;
     * - ACCEPTED_HASHDIGEST_ALGORITHMS - SHA-256, SHA-512.
     * should succeed.
     */
    @Test
    public void successOnAlgorithmIdentifier() throws Exception {
        // given
        workerConfig.setProperty(CLIENTSIDEHASHING, TRUE);
        workerConfig.setProperty(ALLOW_CLIENTSIDEHASHING_OVERRIDE, TRUE);
        workerConfig.setProperty(ACCEPTED_HASHDIGEST_ALGORITHMS, "SHA-256,SHA-512");
        helper.init(workerConfig, workerConfigErrors);
        requestMetadataMap.put(USING_CLIENTSUPPLIED_HASH_PROPERTY, TRUE);
        requestMetadataMap.put(CLIENTSIDE_HASHDIGESTALGORITHM_PROPERTY, "SHA-256");
        RequestMetadata.getInstance(requestContext).putAll(requestMetadataMap);
        // when
        final AlgorithmIdentifier algorithmIdentifier = helper.getClientSideHashAlgorithm(requestContext);
        // then
        assertEquals("Should not have errors", Collections.EMPTY_LIST, workerConfigErrors);
        assertNotNull("AlgorithmIdentifier not null", algorithmIdentifier);
        assertEquals("Algorithm should match", NISTObjectIdentifiers.id_sha256, algorithmIdentifier.getAlgorithm());
    }

    /**
     * We test getClientSideHashAlgorithmName, if:
     * - CLIENTSIDE_HASHDIGESTALGORITHM_PROPERTY - unknown algorithm.
     * should throw IllegalRequestException because of CLIENTSIDE_HASHDIGESTALGORITHM_PROPERTY.
     */
    @Test
    public void failureOnAlgorithmNameWithUnknownAlgorithm() throws Exception {
        // given
        workerConfig.setProperty(CLIENTSIDEHASHING, TRUE);
        workerConfig.setProperty(ALLOW_CLIENTSIDEHASHING_OVERRIDE, TRUE);
        workerConfig.setProperty(ACCEPTED_HASHDIGEST_ALGORITHMS, "");
        helper.init(workerConfig, workerConfigErrors);
        requestMetadataMap.put(USING_CLIENTSUPPLIED_HASH_PROPERTY, TRUE);
        requestMetadataMap.put(CLIENTSIDE_HASHDIGESTALGORITHM_PROPERTY, "XYZ");
        RequestMetadata.getInstance(requestContext).putAll(requestMetadataMap);
        // then
        exceptionRule.expect(IllegalRequestException.class);
        exceptionRule.expectMessage("Client-side hashing request must specify hash algorithm used");
        // when
        helper.getClientSideHashAlgorithmName(requestContext);
    }

    /**
     * We test getClientSideHashAlgorithmName, if:
     * - CLIENTSIDE_HASHDIGESTALGORITHM_PROPERTY - SHA-256;
     * - ACCEPTED_HASHDIGEST_ALGORITHMS - SHA-512.
     * should throw IllegalRequestException because of mismatch of accepted algorithms.
     */
    @Test
    public void failureOnAlgorithmNameWithOtherAcceptedHashDigestAlgorithms() throws Exception {
        // given
        workerConfig.setProperty(CLIENTSIDEHASHING, TRUE);
        workerConfig.setProperty(ALLOW_CLIENTSIDEHASHING_OVERRIDE, TRUE);
        workerConfig.setProperty(ACCEPTED_HASHDIGEST_ALGORITHMS, "SHA-512");
        helper.init(workerConfig, workerConfigErrors);
        requestMetadataMap.put(USING_CLIENTSUPPLIED_HASH_PROPERTY, TRUE);
        requestMetadataMap.put(CLIENTSIDE_HASHDIGESTALGORITHM_PROPERTY, "SHA-256");
        RequestMetadata.getInstance(requestContext).putAll(requestMetadataMap);
        // then
        exceptionRule.expect(IllegalRequestException.class);
        exceptionRule.expectMessage("Client specified a non-accepted digest hash algorithm");
        // when
        helper.getClientSideHashAlgorithmName(requestContext);
    }

    /**
     * We test getClientSideHashAlgorithm, if:
     * - CLIENTSIDE_HASHDIGESTALGORITHM_PROPERTY - SHA-256;
     * - ACCEPTED_HASHDIGEST_ALGORITHMS - SHA-256, SHA-512.
     * should succeed.
     */
    @Test
    public void successOnAlgorithmName() throws Exception {
        // given
        workerConfig.setProperty(CLIENTSIDEHASHING, TRUE);
        workerConfig.setProperty(ALLOW_CLIENTSIDEHASHING_OVERRIDE, TRUE);
        workerConfig.setProperty(ACCEPTED_HASHDIGEST_ALGORITHMS, "SHA-256,SHA-512");
        helper.init(workerConfig, workerConfigErrors);
        requestMetadataMap.put(USING_CLIENTSUPPLIED_HASH_PROPERTY, TRUE);
        requestMetadataMap.put(CLIENTSIDE_HASHDIGESTALGORITHM_PROPERTY, "SHA-256");
        RequestMetadata.getInstance(requestContext).putAll(requestMetadataMap);
        // when
        final String algorithmName = helper.getClientSideHashAlgorithmName(requestContext);
        // then
        assertEquals("Should not have errors", Collections.EMPTY_LIST, workerConfigErrors);
        assertEquals("Algorithm name should match", "SHA-256", algorithmName);
    }
}
