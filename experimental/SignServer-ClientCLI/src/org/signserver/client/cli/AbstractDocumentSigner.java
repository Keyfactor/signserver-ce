/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.signserver.client.cli;

import java.io.IOException;
import java.io.OutputStream;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;

/**
 *
 * @author markus
 */
public abstract class AbstractDocumentSigner implements DocumentSigner {

    private static final String ENCODING_NONE = "none";
    private static final String ENCODING_BASE64 = "base64";

    public AbstractDocumentSigner() {
    }

    public void sign(final byte[] data, final String encoding, final OutputStream out) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException, IOException {
        doSign(data, encoding, out);
    }

    public void sign(final byte[] data, final String encoding) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException, IOException {
        sign(data, encoding, System.out);
    }

    public void sign(final byte[] data) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException, IOException {
        sign(data, ENCODING_NONE, System.out);
    }

    public void sign(final byte[] data, final OutputStream out) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException, IOException {
        doSign(data, ENCODING_NONE, out);
    }

    protected abstract void doSign(final byte[] data, final String encoding,
            final OutputStream out) throws IllegalRequestException,
                CryptoTokenOfflineException, SignServerException,
                IOException;

}
