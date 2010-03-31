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
public interface DocumentSigner {

    void sign(final byte[] data, final String encoding, final OutputStream out) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException, IOException;

    void sign(final byte[] data, final String encoding) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException, IOException;

    void sign(final byte[] data) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException, IOException;

    void sign(final byte[] data, final OutputStream out) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException, IOException;

}
