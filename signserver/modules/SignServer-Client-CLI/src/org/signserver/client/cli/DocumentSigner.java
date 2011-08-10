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
package org.signserver.client.cli;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Map;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;

/**
 * Interface for classes that can sign documents.
 *
 * @author Markus Kilås
 * $Id$
 */
public interface DocumentSigner {

    void sign(final byte[] data, final String encoding, final OutputStream out, final Map<String,Object> requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException, IOException;

    void sign(final byte[] data, final String encoding, final Map<String,Object> requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException, IOException;

    void sign(final byte[] data) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException, IOException;

    void sign(final byte[] data, final OutputStream out, final Map<String,Object> requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException, IOException;

}
