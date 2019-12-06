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
package sun.security.pkcs11;

import java.security.spec.AlgorithmParameterSpec;

import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;

/**
 * Using this {@link AlgorithmParameterSpec} allows you to define the public and private PKCS#11 attribute templates when generating an asymmetric
 * key. The class uses another {@link AlgorithmParameterSpec} valid for the provider or a "key size" for key algorithm specification.
 */
@SuppressWarnings("PMD") // This file is only to provide the API. Ignore warnings from unused formal parameters etc
public class P11AsymmetricParameterSpec implements AlgorithmParameterSpec {

    final CK_ATTRIBUTE publicTemplate[];
    final CK_ATTRIBUTE privateTemplate[];
    final AlgorithmParameterSpec algorithmParameterSpec;
    final int keySize;

    /**
     * Specifying of a key with private and public template and a standard key algorithm specification.
     *
     * @param publicTemplate
     * @param privateTemplate
     * @param algorithmParameterSpec
     */
    public P11AsymmetricParameterSpec(
            final CK_ATTRIBUTE publicTemplate[],
            final CK_ATTRIBUTE privateTemplate[],
            final AlgorithmParameterSpec algorithmParameterSpec) {
        throw new RuntimeException("Functionality not available in JRE");
    }

    /**
     * Specifying of a key with private and public template and a key size.
     *
     * @param publicTemplate
     * @param privateTemplate
     * @param keySize
     */
    public P11AsymmetricParameterSpec(
            final CK_ATTRIBUTE publicTemplate[],
            final CK_ATTRIBUTE privateTemplate[],
            final int keySize) {
        throw new RuntimeException("Functionality not available in JRE");
    }
}
