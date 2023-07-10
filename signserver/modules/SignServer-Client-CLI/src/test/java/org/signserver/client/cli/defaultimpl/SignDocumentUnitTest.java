package org.signserver.client.cli.defaultimpl;

import java.util.Map;
import junit.framework.TestCase;
import org.junit.Test;
import static org.junit.Assert.assertEquals;

/**
 *
 * @author Hanna Hansson
 */
public class SignDocumentUnitTest {

    @Test
    public void testbaseUrlPath() {
        String baseUrlPath = "/mysignserver";

        final MockedHTTPDocumentSigner signer
                = new MockedHTTPDocumentSigner(null, 8080, baseUrlPath, "dummy", true, "PDFSigner", null, null, null, null, null, 0);
        DocumentSignerFactory signerFactory = new DocumentSignerFactory(SignDocumentCommand.Protocol.HTTP, new KeyStoreOptions(), "localhost", baseUrlPath, "dummy", 8080, null, null,
                null, null, null, null, 0);

        signerFactory.createSigner("PDFSigner", null, false, false, null);
        assertEquals(baseUrlPath, signer.getBaseUrlPath());
    }

}
