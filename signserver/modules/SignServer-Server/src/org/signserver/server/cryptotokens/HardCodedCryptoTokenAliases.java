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

/**
 * Key aliases used by the HardCodedCryptoToken.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public interface HardCodedCryptoTokenAliases {
    
    String KEY_ALIAS_1 = "key00001";
    
    String KEY_ALIAS_2 = "key00002";
    
    /** CN=End Entity 1, O=Reversed Org, C=SE. **/
    String KEY_ALIAS_3 = "key00003";
    
    /** CN=TS Signer 2, OU=Testing, O=SignServer, C=SE. */
    String KEY_ALIAS_4 = "key00004";
}
