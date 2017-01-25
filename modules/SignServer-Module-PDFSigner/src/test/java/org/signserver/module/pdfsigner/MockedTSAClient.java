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
package org.signserver.module.pdfsigner;

import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.TSAClient;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;

/**
 * An TSAClient that constructs a timestamp response with an extension
 * containing a bitstring of a specified length.
 * 
 * Can for instance be used to the construction of PKCS#7 structures with 
 * timestamp responses of different sizes.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class MockedTSAClient implements TSAClient {

    private int fixedActualSize;
    
    private int tokenSizeEstimate = 4096; // Same value as used by default in TSAClientBouncyCastle
    
    private boolean called;

    public MockedTSAClient(int fixedActualSize) {
        this.fixedActualSize = fixedActualSize;
    }
    
    @Override
    public int getTokenSizeEstimate() {
        return tokenSizeEstimate;
    }

    @Override
    public byte[] getTimeStampToken(PdfPKCS7 caller, byte[] imprint) throws Exception {
        return getTimeStampToken();
    }
    
    protected byte[] getTimeStampToken() throws Exception {
        called = true;
        // Just an list of TTTTTTTTT....
        byte[] data = new byte[fixedActualSize];
        Arrays.fill(data, (byte) 84);
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(new DERBitString(data));
        byte[] result = new DERSequence(vec).getEncoded();
        
        tokenSizeEstimate = result.length + 32; // Same as in TSAClientBouncyCastle
        return result;
    }

    public boolean isCalled() {
        return called;
    }
    
}
