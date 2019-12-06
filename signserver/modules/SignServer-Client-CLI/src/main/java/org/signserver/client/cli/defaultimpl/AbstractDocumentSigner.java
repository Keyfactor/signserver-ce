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
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;

/**
 * Abstract implementation of DocumentSigner.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public abstract class AbstractDocumentSigner implements DocumentSigner {

    private static final String ENCODING_NONE = "none";

    public AbstractDocumentSigner() {
    }

    @Override
    public void sign(final InputStream data, long size, final String encoding, 
            final OutputStream out, final Map<String,Object> requestContext)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException, IOException {
        doSign(data, size, encoding, out, requestContext);
    }

    @Override
    public void sign(final InputStream data, long size, final String encoding,
            final Map<String,Object> requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException, IOException {
        sign(data, size, encoding, System.out, requestContext);
    }

    @Override
    public void sign(final InputStream data, long size) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException, IOException {
        sign(data, size, ENCODING_NONE, new HashMap<String, Object>());
    }

    @Override
    public void sign(final InputStream data, long size, final OutputStream out,
            final Map<String, Object> requestContext) throws
            IllegalRequestException, CryptoTokenOfflineException,
            SignServerException, IOException {
        doSign(data, size, ENCODING_NONE, out, requestContext);
    }

    protected abstract void doSign(final InputStream data, final long size, final String encoding,
            final OutputStream out, final Map<String,Object> requestContext)
            throws IllegalRequestException,
                CryptoTokenOfflineException, SignServerException,
                IOException;

}
