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
package org.signserver.module.pdfsigner;

import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Set;
import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.junit.Test;
import static org.junit.Assert.*;
import org.signserver.common.RequestMetadata;
import org.signserver.common.WorkerConfig;

/**
 * Unit test for the PDFSignerParameters class.
 *
 * Note: Some cases are already covered in PDFSignerUnitTest.
 *
 * @see PDFSignerUnitTest
 * @author Markus Kilås
 * @version $Id$
 */
public class PDFSignerParametersUnitTest {
    
    private static final Logger LOG = Logger.getLogger(PDFSignerParametersUnitTest.class);

    /**
     * Test overriding ADD_VISIBLE_SIGNATURE.
     * @throws Exception in case of error
     */
    @Test
    public void testOverrideAddVisibleSignature() throws Exception {
        LOG.info("testOverrideAddVisibleSignature");

        // given
        final WorkerConfig config = createWorkerConfig();
        final RequestMetadata requestMetadata = new RequestMetadata();
        requestMetadata.put(PDFSigner.ADD_VISIBLE_SIGNATURE, "true");
        final Set<String> allowPropertyOverride = new HashSet<>(Arrays.asList(PDFSigner.ADD_VISIBLE_SIGNATURE));
        final LinkedList<String> configErrors = new LinkedList<>();
        
        // when
        PDFSignerParameters instance = new PDFSignerParameters(101, config, configErrors, requestMetadata, allowPropertyOverride);
        
        // then
        assertTrue("ADD_VISIBLE_SIGNATURE overridden", 
                instance.isAdd_visible_signature());
    }

    /**
     * Test overriding VISIBLE_SIGNATURE_PAGE.
     * @throws Exception in case of error
     */
    @Test
    public void testOverrideVisible_sig_page() throws Exception {
        LOG.info("testOverrideVisible_sig_page");

        // given
        final WorkerConfig config = createWorkerConfig();
        config.setProperty(PDFSigner.ADD_VISIBLE_SIGNATURE, "true");
        config.setProperty(PDFSigner.VISIBLE_SIGNATURE_PAGE, "3");
        final RequestMetadata requestMetadata = new RequestMetadata();
        requestMetadata.put(PDFSigner.VISIBLE_SIGNATURE_PAGE, "4");
        final Set<String> allowPropertyOverride = new HashSet<>(Arrays.asList(PDFSigner.VISIBLE_SIGNATURE_PAGE));
        final LinkedList<String> configErrors = new LinkedList<>();
        
        // when
        PDFSignerParameters instance = new PDFSignerParameters(101, config, configErrors, requestMetadata, allowPropertyOverride);
        
        // then
        assertEquals("VISIBLE_SIGNATURE_PAGE overridden", "4", instance.getVisible_sig_page());
    }

    /**
     * Test overriding VISIBLE_SIGNATURE_RECTANGLE.
     * @throws Exception in case of error
     */
    @Test
    public void testOverrideVisible_sig_rectangle() throws Exception {
        LOG.info("testOverrideVisible_sig_rectangle");

        // given
        final WorkerConfig config = createWorkerConfig();
        config.setProperty(PDFSigner.ADD_VISIBLE_SIGNATURE, "true");
        config.setProperty(PDFSigner.VISIBLE_SIGNATURE_RECTANGLE, "3,4,5,6");
        final RequestMetadata requestMetadata = new RequestMetadata();
        requestMetadata.put(PDFSigner.VISIBLE_SIGNATURE_RECTANGLE, "7,8,9,10");
        final Set<String> allowPropertyOverride = new HashSet<>(Arrays.asList(PDFSigner.VISIBLE_SIGNATURE_RECTANGLE));
        final LinkedList<String> configErrors = new LinkedList<>();
        
        // when
        PDFSignerParameters instance = new PDFSignerParameters(101, config, configErrors, requestMetadata, allowPropertyOverride);
        
        // then
        assertEquals("VISIBLE_SIGNATURE_RECTANGLE overridden", "7,8,9,10", instance.getVisible_sig_rectangle());
        assertEquals("llx overridden", 7, instance.getVisible_sig_rectangle_llx());
        assertEquals("lly overridden", 8, instance.getVisible_sig_rectangle_lly());
        assertEquals("urx overridden", 9, instance.getVisible_sig_rectangle_urx());
        assertEquals("ury overridden", 10, instance.getVisible_sig_rectangle_ury());
    }

    /**
     * Test overriding USE_TIMESTAMP with old value true.
     * @throws Exception in case of error
     */
    @Test
    public void testOverrideUseTimestampTrue() throws Exception {
        LOG.info("testOverrideUseTimestampTrue");

        // given
        final WorkerConfig config = createWorkerConfig();
        config.setProperty("USE_TIMESTAMP", "true");
        config.setProperty("TSA_WORKER", "TimeStampSigner1");
        
        final RequestMetadata requestMetadata = new RequestMetadata();
        requestMetadata.put(PDFSigner.USE_TIMESTAMP, "false");
        final Set<String> allowPropertyOverride = new HashSet<>(Arrays.asList(PDFSigner.USE_TIMESTAMP));
        final LinkedList<String> configErrors = new LinkedList<>();
        
        // when
        PDFSignerParameters instance = new PDFSignerParameters(101, config, configErrors, requestMetadata, allowPropertyOverride);
        
        // then
        assertFalse("USE_TIMESTAMP overridden", instance.isUseTimestamp());
    }
    
    /**
     * Test overriding USE_TIMESTAMP with old value false.
     * @throws Exception in case of error
     */
    @Test
    public void testOverrideUseTimestampFalse() throws Exception {
        LOG.info("testOverrideUseTimestampFalse");

        // given
        final WorkerConfig config = createWorkerConfig();
        config.setProperty("USE_TIMESTAMP", "false");
        config.setProperty("TSA_WORKER", "TimeStampSigner1");
        
        final RequestMetadata requestMetadata = new RequestMetadata();
        requestMetadata.put(PDFSigner.USE_TIMESTAMP, "true");
        final Set<String> allowPropertyOverride = new HashSet<>(Arrays.asList(PDFSigner.USE_TIMESTAMP));
        final LinkedList<String> configErrors = new LinkedList<>();
        
        // when
        PDFSignerParameters instance = new PDFSignerParameters(101, config, configErrors, requestMetadata, allowPropertyOverride);
        
        // then
        assertTrue("USE_TIMESTAMP overridden", instance.isUseTimestamp());
    }

    /**
     * Test overriding EMBED_CRL.
     * @throws Exception in case of error
     */
    @Test
    public void testOverrideEmbedCrl() throws Exception {
        LOG.info("testOverrideEmbedCrl");

        // given
        final WorkerConfig config = createWorkerConfig();
        config.setProperty(PDFSigner.EMBED_CRL, "false");
        
        final RequestMetadata requestMetadata = new RequestMetadata();
        requestMetadata.put(PDFSigner.EMBED_CRL, "true");
        final Set<String> allowPropertyOverride = new HashSet<>(Arrays.asList(PDFSigner.EMBED_CRL));
        final LinkedList<String> configErrors = new LinkedList<>();
        
        // when
        PDFSignerParameters instance = new PDFSignerParameters(101, config, configErrors, requestMetadata, allowPropertyOverride);
        
        // then
        assertTrue("EMBED_CRL overridden", instance.isEmbed_crl());
    }

    /**
     * Test overriding EMBED_OCSP_RESPONSE.
     * @throws Exception in case of error
     */
    @Test
    public void testOverrideEmbedOcspResponse() throws Exception {
        LOG.info("testOverrideEmbedOcspResponse");

        // given
        final WorkerConfig config = createWorkerConfig();
        config.setProperty(PDFSigner.EMBED_OCSP_RESPONSE, "false");
        
        final RequestMetadata requestMetadata = new RequestMetadata();
        requestMetadata.put(PDFSigner.EMBED_OCSP_RESPONSE, "true");
        final Set<String> allowPropertyOverride = new HashSet<>(Arrays.asList(PDFSigner.EMBED_OCSP_RESPONSE));
        final LinkedList<String> configErrors = new LinkedList<>();
        
        // when
        PDFSignerParameters instance = new PDFSignerParameters(101, config, configErrors, requestMetadata, allowPropertyOverride);
        
        // then
        assertTrue("EMBED_OCSP_RESPONSE overridden", instance.isEmbed_ocsp_response());
    }

    /**
     * Test overriding REMOVE_PERMISSIONS.
     * @throws Exception in case of error
     */
    @Test
    public void testOverrideRemovePermissions() throws Exception {
        LOG.info("testOverrideRemovePermissions");

        // given
        final WorkerConfig config = createWorkerConfig();
        
        final RequestMetadata requestMetadata = new RequestMetadata();
        requestMetadata.put(PDFSigner.REMOVE_PERMISSIONS, "ALLOW_FILL_IN,ALLOW_MODIFY_CONTENTS");
        final Set<String> allowPropertyOverride = new HashSet<>(Arrays.asList(PDFSigner.REMOVE_PERMISSIONS));
        final LinkedList<String> configErrors = new LinkedList<>();
        
        // when
        PDFSignerParameters instance = new PDFSignerParameters(101, config, configErrors, requestMetadata, allowPropertyOverride);
        
        // then
        assertEquals("REMOVE_PERMISSIONS overridden", 
                new HashSet<>(Arrays.asList("ALLOW_FILL_IN", "ALLOW_MODIFY_CONTENTS")),
                instance.getRemovePermissions());
    }

    /**
     * Test overriding SET_PERMISSIONS.
     * @throws Exception in case of error
     */
    @Test
    public void testOverrideSetPermissions() throws Exception {
        LOG.info("testOverrideSetPermissions");

        // given
        final WorkerConfig config = createWorkerConfig();
        
        final RequestMetadata requestMetadata = new RequestMetadata();
        requestMetadata.put(PDFSigner.SET_PERMISSIONS, "ALLOW_FILL_IN,ALLOW_DEGRADED_PRINTING");
        final Set<String> allowPropertyOverride = new HashSet<>(Arrays.asList(PDFSigner.SET_PERMISSIONS));
        final LinkedList<String> configErrors = new LinkedList<>();
        
        // when
        PDFSignerParameters instance = new PDFSignerParameters(101, config, configErrors, requestMetadata, allowPropertyOverride);
        
        // then
        assertEquals("SET_PERMISSIONS overridden", 
                Permissions.fromSet(Arrays.asList("ALLOW_FILL_IN", "ALLOW_DEGRADED_PRINTING"), true),
                instance.getSetPermissions());
    }

    /**
     * Test overriding SET_OWNERPASSWORD.
     * @throws Exception in case of error
     */
    @Test
    public void testOverrideSetOwnerPassword() throws Exception {
        LOG.info("testOverrideSetOwnerPassword");

        // given
        final WorkerConfig config = createWorkerConfig();
        
        final RequestMetadata requestMetadata = new RequestMetadata();
        requestMetadata.put(PDFSigner.SET_OWNERPASSWORD, "newPassword789");
        final Set<String> allowPropertyOverride = new HashSet<>(Arrays.asList(PDFSigner.SET_OWNERPASSWORD));
        final LinkedList<String> configErrors = new LinkedList<>();
        
        // when
        PDFSignerParameters instance = new PDFSignerParameters(101, config, configErrors, requestMetadata, allowPropertyOverride);
        
        // then
        assertEquals("REMOVE_PERMISSIONS overridden", 
                "newPassword789",
                instance.getSetOwnerPassword());
    }

    /**
     * Test overriding VISIBLE_SIGNATURE_CUSTOM_IMAGE_BASE64.
     * @throws Exception in case of error
     */
    @Test
    public void testOverrideVisibleSignatureCustomImageBase64() throws Exception {
        LOG.info("testOverrideVisibleSignatureCustomImageBase64");

        // given
        final WorkerConfig config = createWorkerConfig();

        final RequestMetadata requestMetadata = new RequestMetadata();
        final String image = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVQI12NQsDgKAAGZAR5n3WUAAAAAAElFTkSuQmCC";
        requestMetadata.put(PDFSigner.ADD_VISIBLE_SIGNATURE, "true");
        requestMetadata.put(PDFSigner.VISIBLE_SIGNATURE_CUSTOM_IMAGE_BASE64, image);
        final Set<String> allowPropertyOverride = new HashSet<>(Arrays.asList(PDFSigner.VISIBLE_SIGNATURE_CUSTOM_IMAGE_BASE64, PDFSigner.ADD_VISIBLE_SIGNATURE));
        final LinkedList<String> configErrors = new LinkedList<>();
        
        // when
        PDFSignerParameters instance = new PDFSignerParameters(101, config, configErrors, requestMetadata, allowPropertyOverride);
        
        // then
        assertEquals("VISIBLE_SIGNATURE_CUSTOM_IMAGE_BASE64 overridden", image, instance.getVisible_sig_custom_image_base64());
    }

    /**
     * @return Some minimal generic default worker config
     */
    private WorkerConfig createWorkerConfig() {
        final WorkerConfig result = new WorkerConfig();
        result.setProperty("TYPE", "PROCESSABLE");
        result.setProperty("NAME", "MyWorker");
        return result;
    }
    
}
