/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package sun.security.pkcs11;

import java.security.Key;
import sun.security.pkcs11.wrapper.PKCS11Exception;

/**
 * Extra utilities extending the sun PKCS#11 implementation.
 * @version $Id: CESeCoreUtils.java 25864 2017-05-17 13:46:10Z anatom $
 *
 */
public class CESeCoreUtils {
    /**
     * Sets the CKA_MODIFIABLE attribute of a key object to false.
     * @param providerName The registered name of the provider. If the provider is not an instance of {@link SunPKCS11} then nothing will be done.
     * @param key The key object. If the object is not an instance of {@link P11Key} then nothing will be done.
     * @return true if {@link SunPKCS11} provider and {@link P11Key} key and CKA_MODIFIABLE is not already modified and was actually modified.
     * @throws PKCS11Exception
     */
    public static boolean makeKeyUnmodifiable(final String providerName, final Key key) throws PKCS11Exception {
        throw new RuntimeException("Functionality not available in JRE");
    }
    /**
     * Check if the attribute CKA_MODIFIABLE is true.
     * @param providerName The registered name of the provider. If the provider is not an instance of {@link SunPKCS11} then false is returned.
     * @param key The key object. If the object is not an instance of {@link P11Key} then false is returned.
     * @return true if the attribute is false.
     * @throws PKCS11Exception
     */
    public static boolean isKeyModifiable(final String providerName, final Key key) throws PKCS11Exception {
        throw new RuntimeException("Functionality not available in JRE");
    }
    /**
     * Writes info about security related attributes.
     * @param providerName The registered name of the provider. If the provider is not an instance of {@link SunPKCS11} then false is returned.
     * @param key The key object. If the object is not an instance of {@link P11Key} then false is returned.
     * @param sb Buffer to write to.
     * @throws PKCS11Exception
     */
    public static void securityInfo(final String providerName, final Key key, final StringBuilder sb) throws PKCS11Exception {
        throw new RuntimeException("Functionality not available in JRE");
    }
    
}
