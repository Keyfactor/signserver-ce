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

import java.io.IOException;
import java.io.OutputStream;
import java.util.Map;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;

/**
 * Abstract implementation of SODSigner.
 *
 * @author Markus Kilas
 * @version $Id$
 */
public abstract class AbstractSODSigner implements SODSigner {

    private static final String ENCODING_BINARY = "binary";

    public AbstractSODSigner() {
    }

    @Override
    public void sign(final Map<Integer, byte[]> dataGroups, final String encoding, final OutputStream out) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException, IOException {
        doSign(dataGroups, encoding, out);
    }

    @Override
    public void sign(final Map<Integer, byte[]> dataGroups, final String encoding) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException, IOException {
        sign(dataGroups, encoding, System.out);
    }

    @Override
    public void sign(final Map<Integer, byte[]> dataGroups) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException, IOException {
        sign(dataGroups, ENCODING_BINARY, System.out);
    }

    @Override
    public void sign(final Map<Integer, byte[]> dataGroups, final OutputStream out) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException, IOException {
        doSign(dataGroups, ENCODING_BINARY, out);
    }

    protected abstract void doSign(final Map<Integer, byte[]> dataGroups, final String encoding,
            final OutputStream out) throws IllegalRequestException,
                CryptoTokenOfflineException, SignServerException,
                IOException;

}
