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

import java.util.Iterator;
import java.util.ServiceLoader;
/**
 * Service locator for enabling different crypto token implementations for PKCS11CryptoToken
 *
 * @author Oscar Norman
 * @author Christofer Vikström
 */
public final class CryptoServiceLocatorV2 {

    public static Class<?> getCryptoTokenImplementationClass(boolean dbprot) {
        final Class<?> result;
        Iterator<P11ImplementationProvider> iterator = ServiceLoader.load(P11ImplementationProvider.class).iterator();
        if (iterator.hasNext()) {
            if (!dbprot) {
                result = iterator.next().getCryptoTokenImplementatinClass();
            } else {
                result = iterator.next().getDatabaseProtectionCryptoTokenImplementatinClass();
            }
        } else {
            if (!dbprot) {
                result = org.signserver.server.cryptotokens.LegacyPKCS11CryptoToken.class;
            } else {
                result = org.cesecore.keys.token.LegacyPKCS11CryptoToken.class;
            }
        }
        return result;
    }
}
