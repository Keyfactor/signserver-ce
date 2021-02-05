/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.dnssec.signer;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import org.signserver.module.dnssec.common.RRsetId;
import org.signserver.module.dnssec.common.ZoneClientHelper;
import org.signserver.module.dnssec.common.ZoneHelper;
import static org.signserver.module.dnssec.common.ZoneHelper.INCREMENT_SERIAL;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

/**
 * Server-side zone file signer implementation of the ZoneSignatureCreator.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ZoneFileServerSideSignatureCreator
        extends BaseServerSideSignatureCreator {

    public ZoneFileServerSideSignatureCreator(ZoneClientHelper.Phase1Data d, KeyPair zsk1KeyPair) {
        super(d, zsk1KeyPair);
    }

    @Override
    public RRSIGRecord createRRsetSig(RRsetId id, RRset rrSet, int sigIdCounter)
            throws DNSSEC.DNSSECException, TextParseException, NoSuchAlgorithmException {
        final RRSIGRecord sig =
                DNSSEC.sign(INCREMENT_SERIAL ?
                ZoneHelper.incrementSoa(rrSet) :
                rrSet, d.getDnskeyZSK1(), zsk1KeyPair.getPrivate(),
                d.getTimeSigned(), d.getExpire());
        ZoneHelper.putType(d.getTypesMap(), d.getNsec3Params(),
                           rrSet.getName().toString(), Type.RRSIG);
        
        return sig;
    }
    
}
