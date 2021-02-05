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
 * EC version of AsymmetricParameterSpec.
 *
 * Note: This class needs to contain "EC" in the name due to CESeCore.
 *
 * @author Markus Kilås
 * @version $Id$
 */
class ECP11AsymmetricParameterSpec extends P11AsymmetricParameterSpec {
    
    public ECP11AsymmetricParameterSpec(CK_ATTRIBUTE[] cktrbts, CK_ATTRIBUTE[] cktrbts1, AlgorithmParameterSpec aps) {
        super(cktrbts, cktrbts1, aps);
    }
    
}
