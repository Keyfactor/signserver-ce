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
import java.util.Date;
import org.signserver.module.dnssec.common.RRsetId;
import org.signserver.module.dnssec.common.ZoneClientHelper;
import org.signserver.module.dnssec.common.ZoneHelper;
import static org.signserver.module.dnssec.common.ZoneHelper.INCREMENT_SERIAL;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.DNSSEC.DNSSECException;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

/**
 * Server-side ZIP zone file implementation of ZoneSignatureCreator.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ZipZoneFileServerSideSignatureCreator
        extends BaseServerSideSignatureCreator {

    private final Long minRemainingValidity;
    
    public ZipZoneFileServerSideSignatureCreator(final ZoneClientHelper.Phase1Data d,
                                                 final KeyPair zsk1KeyPair,
                                                 final Long minRemainingValidity) {
        super(d, zsk1KeyPair);
        this.minRemainingValidity = minRemainingValidity;
    }

    @Override
    public RRSIGRecord createRRsetSig(final RRsetId id, final RRset rrset,
                                      final int sigIdCounter) 
        throws DNSSECException, TextParseException, NoSuchAlgorithmException {
        final RRSIGRecord reusableSig
                = d.getParser().getReusableSignatureForRrSet(id);
        
        final boolean hasReusableSig;

        if (reusableSig != null) {
            if (minRemainingValidity == null) {
                throw new IllegalArgumentException("Missing property MIN_REMAINING_VALIDITY");
            }
            final Date notAfter
                    = new Date(d.getTimeSigned().getTime() + minRemainingValidity);

            final Date sigExpire = reusableSig.getExpire();
            final int zsk1Footprint = d.getDnskeyZSK1().getFootprint();
            final int rrsigFootprint = reusableSig.getFootprint();

            hasReusableSig = notAfter.before(sigExpire)
                    && rrsigFootprint == zsk1Footprint;
        } else {
            hasReusableSig = false;
        }

        final RRSIGRecord sig;
        if (hasReusableSig) {
            sig = reusableSig;
        } else {
            sig = DNSSEC.sign(INCREMENT_SERIAL ?
                              ZoneHelper.incrementSoa(rrset) :
                              rrset, d.getDnskeyZSK1(), zsk1KeyPair.getPrivate(),
                              d.getTimeSigned(), d.getExpire());
        }
        ZoneHelper.putType(d.getTypesMap(), d.getNsec3Params(), rrset.getName().toString(), Type.RRSIG);

        return sig;
    }
}
