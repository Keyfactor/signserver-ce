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
import org.signserver.module.dnssec.common.ZoneClientHelper.Phase1Data;
import org.signserver.module.dnssec.common.ZoneSignatureCreator;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.NSEC3Record;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;

/**
 * Abstract base implementation for server-side ZoneSignatureCreatorS.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public abstract class BaseServerSideSignatureCreator implements ZoneSignatureCreator {

    protected final Phase1Data d;
    protected final KeyPair zsk1KeyPair;
    
    public BaseServerSideSignatureCreator(final Phase1Data d,
                                      final KeyPair zsk1KeyPair) {
        this.d = d;
        this.zsk1KeyPair = zsk1KeyPair;
    }
    
    @Override
    public RRSIGRecord createNsec3ParamsSig() throws DNSSEC.DNSSECException {
        final RRSIGRecord sig =
                DNSSEC.sign(new RRset(d.getNsec3Params()),
                            d.getDnskeyZSK1(),
                            zsk1KeyPair.getPrivate(),
                            d.getTimeSigned(), d.getExpire());
        
        return sig;
    }

    @Override
    public RRSIGRecord createNsec3RecordSig(NSEC3Record nsec3, int sigIdCounter)
            throws DNSSEC.DNSSECException {
        final RRSIGRecord sig =
                DNSSEC.sign(new RRset(nsec3), d.getDnskeyZSK1(),
                            zsk1KeyPair.getPrivate(), d.getTimeSigned(),
                            d.getExpire());

        return sig;
    }
}
