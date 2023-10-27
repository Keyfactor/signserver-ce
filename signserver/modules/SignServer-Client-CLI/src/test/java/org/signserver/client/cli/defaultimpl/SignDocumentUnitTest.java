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
package org.signserver.client.cli.defaultimpl;

import java.util.Map;
import junit.framework.TestCase;
import org.junit.Test;
import static org.junit.Assert.assertEquals;

/**
 * Unit tests for basepathurl.
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
