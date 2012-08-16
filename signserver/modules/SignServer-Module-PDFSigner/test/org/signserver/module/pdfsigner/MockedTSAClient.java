/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.module.pdfsigner;

import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.TSAClient;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;

/**
 *
 * @author markus
 */
public class MockedTSAClient implements TSAClient {

    private int fixedActualSize;
    
    private int tokenSizeEstimate = 4096; // Same value as used by default in TSAClientBouncyCastle

    public MockedTSAClient(int fixedActualSize) {
        this.fixedActualSize = fixedActualSize;
    }
    
    public int getTokenSizeEstimate() {
        return tokenSizeEstimate;
    }

    public byte[] getTimeStampToken(PdfPKCS7 caller, byte[] imprint) throws Exception {
        return getTimeStampToken();
    }
    
    protected byte[] getTimeStampToken() throws Exception {
        // Just an list of TTTTTTTTT....
        
        byte[] data = new byte[fixedActualSize];
        Arrays.fill(data, (byte) 84);
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(new DERBitString(data));
        byte[] result = new DERSequence(vec).getEncoded();
        
        tokenSizeEstimate = result.length + 32; // Same as in TSAClientBouncyCastle
        return result;
    }
    
}
