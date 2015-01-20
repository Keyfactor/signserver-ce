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
package org.signserver.server.cryptotokens;

import java.security.cert.Certificate;
import java.util.List;
import org.signserver.common.CryptoTokenOfflineException;

/**
 * Third version of the crypto token interface.
 * Adding support for importing certificates to crypto tokens.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public interface ICryptoTokenV3 extends ICryptoTokenV2 {
    
    /**
     * Import certificate chain to a crypto token.
     * 
     * @param certChain Certificate chain to import, should contain signing certificate
     * @param alias Key alias to import certificate chain in
     * @param athenticationCode Alias-specific authentication code. If this is null
     *                          uses the token's authentication code (set when activating)
     * @throws CryptoTokenOfflineException
     * @throws IllegalArgumentException 
     */
    void importCertificateChain(List<Certificate> certChain, String alias,
            char[] athenticationCode)
            throws CryptoTokenOfflineException, IllegalArgumentException;
}
