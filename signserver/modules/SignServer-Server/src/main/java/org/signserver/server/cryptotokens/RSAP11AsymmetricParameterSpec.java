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

import java.security.spec.AlgorithmParameterSpec;
import sun.security.pkcs11.P11AsymmetricParameterSpec;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;

/**
 * RSA version of AsymmetricParameterSpec.
 *
 * Note: This class needs to contain "RSA" in the name due to CESeCore.
 *
 * @author Markus Kilås
 * @version $Id$
 */
class RSAP11AsymmetricParameterSpec extends P11AsymmetricParameterSpec {
    
    public RSAP11AsymmetricParameterSpec(CK_ATTRIBUTE[] cktrbts, CK_ATTRIBUTE[] cktrbts1, AlgorithmParameterSpec aps) {
        super(cktrbts, cktrbts1, aps);
    }
    
}
