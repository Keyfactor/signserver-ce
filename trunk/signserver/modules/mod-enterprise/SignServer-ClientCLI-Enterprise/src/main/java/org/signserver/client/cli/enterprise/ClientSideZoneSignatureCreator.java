/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.client.cli.enterprise;

import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashMap;
import org.signserver.module.dnssec.common.RRsetId;
import org.signserver.module.dnssec.common.ZoneClientHelper;
import org.signserver.module.dnssec.common.ZoneClientHelper.Phase1Data;
import org.signserver.module.dnssec.common.ZoneHelper;
import static org.signserver.module.dnssec.common.ZoneHelper.INCREMENT_SERIAL;
import org.signserver.module.dnssec.common.ZoneSignatureCreator;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.NSEC3Record;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

/**
 * Client-side implementation of ZoneSignatureCreator.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ClientSideZoneSignatureCreator implements ZoneSignatureCreator {

    private final Phase1Data d;
    private final boolean hashingState;
    private final Long minRemainingValidity;
    private final HashMap<String, byte[]> sigId2signatureBytes;

    ClientSideZoneSignatureCreator(final Phase1Data d, final boolean hashingState,
                                   final Long minRemainingValidity,
                                   final HashMap<String, byte[]> sigId2signatureBytes) {
        this.d = d;
        this.hashingState = hashingState;
        this.minRemainingValidity = minRemainingValidity;
        this.sigId2signatureBytes = sigId2signatureBytes;
    }
    
    @Override
    public RRSIGRecord createNsec3ParamsSig() throws DNSSEC.DNSSECException {
        return d.getNsec3ParamsSig();
    }

    @Override
    public RRSIGRecord createRRsetSig(RRsetId id, RRset rrSet, int sigIdCounter) throws DNSSEC.DNSSECException, TextParseException, NoSuchAlgorithmException {
        final RRSIGRecord reusableSig
                = d.getParser().getReusableSignatureForRrSet(id);        
        final boolean hasReusableSig;

        if (reusableSig != null) {
            if (minRemainingValidity == null) {
                throw new IllegalArgumentException("Missing MIN_REMAINING_VALIDITY extraoption");
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

        RRSIGRecord sig = null;
        final String newSigId = String.valueOf(sigIdCounter);
        
        if (hasReusableSig) {
            if (!hashingState) {
                sig = reusableSig;
            }
        } else {
            if (hashingState) {
                final RRset newRRset =
                        INCREMENT_SERIAL ? ZoneHelper.incrementSoa(rrSet) : rrSet;
                final RRSIGRecord emptySigRecord = ZoneHelper.createRrsigRecord(
                    newRRset, d.getDnskeyZSK1(), d.getTimeSigned(), d.getExpire());
                d.getRrsetId2sigId().put(id, newSigId);
                d.getSigMap().put(newSigId, new ZoneClientHelper.TbsRecord(emptySigRecord, newRRset));
            } else {
                String realSigId = d.getRrsetId2sigId().get(id);
                final ZoneClientHelper.TbsRecord tbsRecord = d.getSigMap().get(realSigId);
                final RRSIGRecord emptySigFromBefore = tbsRecord.getSigRecord();
                //        DNSSEC.sign(INCREMENT_SERIAL ?
                //        ZoneHelper.incrementSoa(rrset) :
                //        rrset, dnskeyZSK1, zsk1KeyPair.getPrivate(), timeSigned, expire);
                
                final RRSIGRecord finalSigRecord = ZoneHelper.createWithSignature(emptySigFromBefore, sigId2signatureBytes.get(realSigId));
                
                sig = finalSigRecord;
            }
        }
        ZoneHelper.putType(d.getTypesMap(), d.getNsec3Params(), rrSet.getName().toString(), Type.RRSIG);
        
        return sig;
    }

    @Override
    public RRSIGRecord createNsec3RecordSig(NSEC3Record nsec3, int sigIdCounter) throws DNSSEC.DNSSECException {
        RRSIGRecord sig = null;

        if (hashingState) {
            final RRset rrset = new RRset(nsec3);
            final RRSIGRecord emptySigRecord =
                    ZoneHelper.createRrsigRecord(rrset, d.getDnskeyZSK1(),
                                                 d.getTimeSigned(), d.getExpire());
            final String newSigId = String.valueOf(++sigIdCounter);
            d.getRrsetId2sigId().put(RRsetId.fromRecord(nsec3), newSigId);
            d.getSigMap().put(newSigId, new ZoneClientHelper.TbsRecord(emptySigRecord, rrset));
        } else {
            final String sigId = d.getRrsetId2sigId().get(RRsetId.fromRecord(nsec3));
            final ZoneClientHelper.TbsRecord tbsRecord = d.getSigMap().get(sigId);
            final RRSIGRecord emptySigFromBefore = tbsRecord.getSigRecord();
            final RRSIGRecord finalSigRecord = ZoneHelper.createWithSignature(emptySigFromBefore, sigId2signatureBytes.get(sigId));

            sig = finalSigRecord;
        }

        return sig;
    }
}
