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
package org.signserver.test.utils.builders;

import java.math.BigInteger;
import java.security.*;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Hex;

/**
 * Utility methods for key generation.
 *
 *
 * @version $Id$
 */
public class CryptoUtils {
    
    public static KeyPair generateEcCurve(String spec) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(spec);
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
        g.initialize(ecSpec, new SecureRandom());
        return g.generateKeyPair();
    }

    public static KeyPair generateEcExplicit() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        ECCurve curve = new ECCurve.Fp(
            new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
            new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
            new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b
        org.bouncycastle.jce.spec.ECParameterSpec ecSpec = new org.bouncycastle.jce.spec.ECParameterSpec(
            curve,
            curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
            new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307")); // n
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
        g.initialize(ecSpec, new SecureRandom());
        return g.generateKeyPair();
    }

    public static KeyPair generateRSA(int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA", "BC");
        g.initialize(keySize, new SecureRandom());
        return g.generateKeyPair();
    }
    
    public static KeyPair generateDSA(int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("DSA", "BC");
        g.initialize(keySize, new SecureRandom());
        return g.generateKeyPair();
    }
}
