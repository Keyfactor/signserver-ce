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
 * Abstract implementation of DocumentValidator.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public abstract class AbstractDocumentValidator implements DocumentValidator {

    private static final String ENCODING_NONE = "none";

    public AbstractDocumentValidator() {
    }

    public void validate(final InputStream in, final long size, final String encoding, 
            final OutputStream out, final Map<String,Object> requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException, IOException {
        doValidate(in, size, encoding, out, requestContext);
    }

    @Override
    public void validate(final InputStream in, final long size, final String encoding) 
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException, IOException {
        validate(in, size, encoding, System.out);
    }

    @Override
    public void validate(final InputStream in, final long size, final Map<String, Object> requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException, IOException {
        validate(in, size, ENCODING_NONE, System.out, requestContext);
    }

    public void validate(final InputStream in, final long size, final OutputStream out, final Map<String,Object> requestContext) 
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException, IOException {
        doValidate(in, size, ENCODING_NONE, out, requestContext);
    }

    protected abstract void doValidate(final InputStream in, final long size, final String encoding,
            final OutputStream out, final Map<String,Object> requestContext) throws IllegalRequestException,
                CryptoTokenOfflineException, SignServerException,
                IOException;

    @Override
    public void validate(final InputStream in, final long size, String encoding, OutputStream out)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException, IOException {
        doValidate(in, size, ENCODING_NONE, System.out, new HashMap<String, Object>());
    }

    @Override
    public void validate(final InputStream in, final long size, OutputStream out)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException, IOException {
        doValidate(in, size, ENCODING_NONE, out, new HashMap<String, Object>());
    }
    
    
}
