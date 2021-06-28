/**
 * Copyright 2012 Emmanuel Bourg
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.signserver.module.msauthcode.signer;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import net.jsign.asn1.authenticode.AuthenticodeSignedData;
import java.util.Arrays;

/**
 * Based on AuthenticodeSignedDataGenerator, but modified to remove the tag and length octets from the DER encoded IDC
 * prior to digestion. RFC 5652 - Cryptographic Message Syntax (section 5.4)
 * 
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class AppxSignedDataGenerator extends CMSSignedDataGenerator {

    public CMSSignedData generate(ASN1ObjectIdentifier contentTypeOID, ASN1Encodable content) throws CMSException, IOException {
        digests.clear();
        
        SignerInfo signerInfo;
        
        byte[] der_idc = content.toASN1Primitive().getEncoded("DER");
        byte[] der_idc_noidlength = Arrays.copyOfRange(der_idc, 2, der_idc.length); 

        if (!_signers.isEmpty()) {
            signerInfo = ((SignerInformation) _signers.get(0)).toASN1Structure();
        } else {
            CMSSignedData sigData = super.generate(new CMSProcessableByteArray(contentTypeOID, der_idc_noidlength));
            signerInfo = sigData.getSignerInfos().iterator().next().toASN1Structure();
        }

        ContentInfo encInfo = new ContentInfo(contentTypeOID, content);
        ASN1Set certificates = new DERSet((ASN1Encodable[]) certs.toArray(new ASN1Encodable[0]));

        ASN1Encodable signedData = new AuthenticodeSignedData(signerInfo.getDigestAlgorithm(), encInfo, certificates, signerInfo);

        ContentInfo contentInfo = new ContentInfo(CMSObjectIdentifiers.signedData, signedData);

        return new CMSSignedData(new CMSProcessableByteArray(contentTypeOID, content.toASN1Primitive().getEncoded("DER")), contentInfo);
    }
}
