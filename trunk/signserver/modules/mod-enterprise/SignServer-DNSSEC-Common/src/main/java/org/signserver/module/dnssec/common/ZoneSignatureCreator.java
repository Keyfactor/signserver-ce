/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.dnssec.common;

import java.security.NoSuchAlgorithmException;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.DNSSEC.DNSSECException;
import org.xbill.DNS.NSEC3Record;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.TextParseException;

/**
 * Interface declaring methods to perform zone signing operations.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public interface ZoneSignatureCreator {
    /**
     * Create a signature record for the NSEC3 parameters.
     *
     * @return NSEC3 parameters signature
     * @throws org.xbill.DNS.DNSSEC.DNSSECException 
     */
    public RRSIGRecord createNsec3ParamsSig() throws DNSSECException;

    /**
     * Create or prepare a signature for an RRSet.
     * In the client-side case, this would prepare the signature to later
     * be created, so it can return null in this case.
     * 
     * @param id Unique RRSet ID
     * @param rrSet RRSet to sign or prepare for
     * @param sigIdCounter Signature ID counter, this will only be meaningful
     *                     in the client-side case, where this is the hash
     *                     number communicated with the ZoneHashSigner
     * @return The signature, or null if only preparation for hash signing was
     *         done
     * @throws org.xbill.DNS.DNSSEC.DNSSECException
     * @throws TextParseException
     * @throws NoSuchAlgorithmException 
     */
    public RRSIGRecord createRRsetSig(RRsetId id, RRset rrSet, int sigIdCounter)
            throws DNSSECException, TextParseException, NoSuchAlgorithmException;

    /**
     * Create or prepare a signature for an NSEC3 record.
     * In the client-side case, this would prepare the signature to later
     * be created, so it can return null in this case.
     *
     * @param nsec3 NSEC3 record to sign or prepare for
     * @param sigIdCounter Signature ID counter, this will only be meaningful
     *                     in the client-side case, where this is the hash
     *                     number communicated with the ZoneHashSigner
     * @return The signature, or null if only preparation for hash signing was
     *         done
     * @throws org.xbill.DNS.DNSSEC.DNSSECException 
     */
    public RRSIGRecord createNsec3RecordSig(NSEC3Record nsec3, int sigIdCounter)
            throws DNSSEC.DNSSECException;
}
