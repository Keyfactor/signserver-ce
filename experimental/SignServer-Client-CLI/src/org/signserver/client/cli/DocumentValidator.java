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
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;

/**
 *
 * @author Markus Kilas
 * $Id: DocumentSigner.java 910 2010-03-31 12:05:34Z netmackan $
 */
public interface DocumentValidator {

    void validate(final byte[] data, final String encoding,
            final OutputStream out) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException, IOException;

    void validate(final byte[] data, final String encoding)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException, IOException;

    void validate(final byte[] data) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException, IOException;

    void validate(final byte[] data, final OutputStream out)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException, IOException;
}
