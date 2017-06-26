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
package org.signserver.module.ooxmlsigner;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Arrays;
import static junit.framework.TestCase.assertNotNull;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import static org.junit.Assert.*;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.test.utils.mock.MockedCryptoToken;

/**
 * Unit tests for the ODFSigner class.
 *
 * System tests (and other tests) are available in the Test-System project.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class OOXMLSignerUnitTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(OOXMLSignerUnitTest.class);

    private static MockedCryptoToken tokenRSA;

    /**
     * predefined docx file in base64 format.
     */
    private static final String TEST_OOXML_DOC =
        "UEsDBBQABgAIAAAAIQBvGmuQfgEAACgGAAATAAgCW0NvbnRlbnRfVHlwZXNdLnhtbCCiBAIooAAC\n" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC0\n" +
        "lM1qwzAQhO+FvoPRtdhKeiil2M6hP8c20PQBFGmdiNqSkDZ/b9+145hSEocm+GIwZr+ZHY+UTrZV\n" +
        "Ga3BB21NxsbJiEVgpFXaLDL2NXuLH1kUUBglSmsgYzsIbJLf3qSznYMQ0bQJGVsiuifOg1xCJUJi\n" +
        "HRj6UlhfCaRXv+BOyG+xAH4/Gj1waQ2CwRhrBsvTDzLgtYJoKjy+i4p0+MZ6xQtr0ViEkBCORc/7\n" +
        "uVo6Y8K5UkuBZJyvjfojGtui0BKUlauKpJIa57yVEAKtVpVJh76r0TxPX6AQqxKj1y1528fhoQz/\n" +
        "U23XTGiycRaW2oUehf61Wmcn4+m268dckE5HroQ2B/8nfQTclUP8oz33rDwYNVBJDuQ+CxTV1FsX\n" +
        "OBXy6ppCXT4FKqauOvCooWvP6fQBkTo9wBkJLblv/eacIp174M1zfHUGDeasZEF3wUzMS7ha78jV\n" +
        "0KLPmtjA/HOw9H/B+4x0/ZPWXxDG4caqp4+0jjf3fP4DAAD//wMAUEsDBBQABgAIAAAAIQAekRq3\n" +
        "8wAAAE4CAAALAAgCX3JlbHMvLnJlbHMgogQCKKAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjJLbSgNBDIbvBd9hyH032woi0tneSKF3IusD\n" +
        "hJnsAXcOzKTavr2jILpQ217m9OfLT9abg5vUO6c8Bq9hWdWg2JtgR99reG23iwdQWchbmoJnDUfO\n" +
        "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";

    /**
     * predefined docx file in base64 format.
     * Having a DOCTYPE with an element in _xmlsignatures/_rels/origin.sigs.rels.
     */
    private static final String TEST_OOXML_DOC_WITH_DOCTYPE =
        "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\n" +
        "8LJtoUEKPEW6DXB5Pz3voVHzNPmVCQf4RoXD+LTpS1fwekaz+qlNVUg7GWAxy51zGhZMXreckeo2\n" +
        "syRv9ZSb43mOAd84fCQkc7u2fXWCq7daoEvMCn9aeUQrLFMWDqhaQ9L66yUfCcbayNliij94YjkK\n" +
        "F0VxY+/+tY93UEsBAhQAFAAAAAgAoXt6RekkG9gCAQAA6QIAAAsAAAAAAAAAAAAAAAAAAAAAAF9y\n" +
        "ZWxzLy5yZWxzUEsBAhQAFAAAAAgAoXt6RSIc9MyiAQAAUwcAABMAAAAAAAAAAAAAAAAAKwEAAFtD\n" +
        "b250ZW50X1R5cGVzXS54bWxQSwECFAAUAAAACAChe3pF6Xvdg2sKAACfHwAANwAAAAAAAAAAAAAA\n" +
        "AAD+AgAAX3htbHNpZ25hdHVyZXMvMzZlNzI4YjItMjk1Ny00YjE3LTg5NzItYmNiZjhiY2QzNzk0\n" +
        "LnhtbFBLAQIUABQAAAAIAKF7ekUAAAAAAgAAAAAAAAAaAAAAAAAAAAAAAAAAAL4NAABfeG1sc2ln\n" +
        "bmF0dXJlcy9vcmlnaW4uc2lnc1BLAQIeAxQAAAAIANN7ekWVGrkS5AAAAGEBAAAlABgAAAAAAAEA\n" +
        "AAC0gfgNAABfeG1sc2lnbmF0dXJlcy9fcmVscy9vcmlnaW4uc2lncy5yZWxzVVQFAAMN5HVUdXgL\n" +
        "AAEE6AMAAAToAwAAUEsBAhQAFAAAAAgAoXt6RaPiXm59AQAA3wIAABAAAAAAAAAAAAAAAAAAOw8A\n" +
        "AGRvY1Byb3BzL2FwcC54bWxQSwECFAAUAAAACAChe3pFV2vd9C8BAACXAgAAEQAAAAAAAAAAAAAA\n" +
        "AADmEAAAZG9jUHJvcHMvY29yZS54bWxQSwECFAAUAAAACAChe3pFoElkvGYCAAA1CAAAEQAAAAAA\n" +
        "AAAAAAAAAABEEgAAd29yZC9kb2N1bWVudC54bWxQSwECFAAUAAAACAChe3pFBeE14v8AAAA/BAAA\n" +
        "HAAAAAAAAAAAAAAAAADZFAAAd29yZC9fcmVscy9kb2N1bWVudC54bWwucmVsc1BLAQIUABQAAAAI\n" +
        "AKF7ekUxXGqbggEAAGQEAAARAAAAAAAAAAAAAAAAABIWAAB3b3JkL2VuZG5vdGVzLnhtbFBLAQIU\n" +
        "ABQAAAAIAKF7ekU1ycOoiAEAAA8FAAASAAAAAAAAAAAAAAAAAMMXAAB3b3JkL2ZvbnRUYWJsZS54\n" +
        "bWxQSwECFAAUAAAACAChe3pFcbmiToIBAABqBAAAEgAAAAAAAAAAAAAAAAB7GQAAd29yZC9mb290\n" +
        "bm90ZXMueG1sUEsBAhQAFAAAAAgAoXt6Ra8YPj8ZAwAA/AcAABEAAAAAAAAAAAAAAAAALRsAAHdv\n" +
        "cmQvc2V0dGluZ3MueG1sUEsBAhQAFAAAAAgAoXt6RcBSglWiBgAAzT8AAA8AAAAAAAAAAAAAAAAA\n" +
        "dR4AAHdvcmQvc3R5bGVzLnhtbFBLAQIUABQAAAAIAKF7ekWWta3iwgUAAFAbAAAVAAAAAAAAAAAA\n" +
        "AAAAAEQlAAB3b3JkL3RoZW1lL3RoZW1lMS54bWxQSwECFAAUAAAACAChe3pFStiKkrQAAAAEAQAA\n" +
        "FAAAAAAAAAAAAAAAAAA5KwAAd29yZC93ZWJTZXR0aW5ncy54bWxQSwUGAAAAABAAEABYBAAAHywA\n" +
        "AAAA";

    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        tokenRSA = generateToken();
    }

    private static MockedCryptoToken generateToken() throws Exception {
        final KeyPair signerKeyPair = CryptoUtils.generateRSA(1024);
        final Certificate[] certChain =
                new Certificate[] {new JcaX509CertificateConverter().getCertificate(new CertBuilder().
                        setSelfSignKeyPair(signerKeyPair).
                        setSignatureAlgorithm("SHA1withRSA")
                        .build())};
        final Certificate signerCertificate = certChain[0];
        return new MockedCryptoToken(signerKeyPair.getPrivate(), signerKeyPair.getPublic(), signerCertificate, Arrays.asList(certChain), "BC");
    }

    /**
     * Test signing with an RSA key.
     * 
     * @throws Exception
     */
    @Test
    public void testSignDocx() throws Exception {
        testBasicOOXMLSign(TEST_OOXML_DOC);
    }

    /**
     * Tests that a document with a DOCTYPE is not allowed.
     * @throws Exception
     */
    @Test
    @SuppressWarnings("ThrowableResultIgnored")
    public void testDTDNotAllowed() throws Exception {
        LOG.info("testDTDNotAllowed");
        try {
            testBasicOOXMLSign(TEST_OOXML_DOC_WITH_DOCTYPE);
            fail("Should have thrown IllegalRequestException as the document contained a DTD");
        } catch (SignServerException expected) {
            if (!expected.getCause().getMessage().contains("DOCTYPE")) {
                LOG.error("Wrong exception message", expected);
                fail("Should be error about doctype: " + expected.getMessage());
            }
        }
    }

    private void testBasicOOXMLSign(final String document) throws Exception {
        WorkerConfig config = new WorkerConfig();

        OOXMLSigner instance = new MockedOOXMLSigner(tokenRSA);
        instance.init(4711, config, null, null);
        final RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-100-1");

        GenericSignRequest request = new GenericSignRequest(100, Base64.decode(document.getBytes(StandardCharsets.UTF_8)));
        GenericSignResponse res = (GenericSignResponse) instance.processData(request, requestContext);

        // Check certificate
        final Certificate signercert = res.getSignerCertificate();
        assertNotNull("Signer certificate", signercert);
    }

}
