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

import org.signserver.module.dnssec.common.ZoneFileParser;
import org.signserver.module.dnssec.common.RRsetId;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.TimeZone;
import org.apache.log4j.Logger;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.RequestMetadata;
import org.signserver.common.data.ReadableData;
import org.signserver.module.dnssec.common.ZoneClientHelper.Phase1Data;
import org.signserver.module.dnssec.common.ZoneHelper;
import org.signserver.module.dnssec.common.ZoneSignatureCreator;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.NSEC3PARAMRecord;
import org.xbill.DNS.NSEC3Record;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

/**
 * DNSSEC server-side signer base class for signing zone & zipzone file.
 *
 * @author Vinay Singh
 * @version $Id$
 */
public abstract class BaseZoneFileServerSideSigner extends BaseZoneSigner {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(BaseZoneFileServerSideSigner.class);
    
    @Override
    protected void signData(ReadableData requestData, RequestContext requestContext, OutputStream outputStream,
                         List<ICryptoInstance> zskCryptoInstances,
                         List<ICryptoInstance> kskCryptoInstances)
            throws TextParseException, NoSuchAlgorithmException,
                   FileNotFoundException, IOException, DNSSEC.DNSSECException,
                   IllegalArgumentException, IllegalRequestException {
        System.setProperty("dnsjava.options", "multiline");

        // Times
        final Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));

        // Comment this out for testing with fixed data (should be removed before release)
        if (fixedTime != null) {
            cal.setTimeInMillis(fixedTime);
            LOG.warn("Using fixed time: " + fixedTime);
        }

        // Use current time for signing and current time + 1 Month for expiration
        final Date timeSigned = cal.getTime();
        cal.add(Calendar.MONTH, 1);
        final Date expire = cal.getTime();

        final List<InputStream> inputStreamsToBeClosed = new ArrayList<>(2);
        try {
            // Parse zone file into RRsets
            final ZoneFileParser parser = extractZoneFileAndParse(requestData, requestContext, zoneName, inputStreamsToBeClosed);

            final HashMap<RRsetId, RRset> rrSetMap = parser.getCurrentRrSetMap();
            final ArrayList<RRsetId> rrSetIds = parser.getCurrentRrSetIds();
            final SOARecord soa = parser.getCurrentSoa();

            // Debug log the results
            if (LOG.isDebugEnabled()) {
                LOG.debug("rrsets: ");

                for (RRsetId id : rrSetIds) {
                    LOG.debug(id.getName() + " " + DClass.string(id.getdClass()) + " " + Type.string(id.getType()));
                    LOG.debug(rrSetMap.get(id));
                }
            }

            // Check that we got a SOA record
            if (soa == null) {
                throw new IllegalRequestException("Unable to parse zone file. Failed to find an SOA.");
            }
            
            // NSEC order
            final HashMap<String, List<Integer>> typesMap = new HashMap<>();
            final NSEC3PARAMRecord nsec3Params = newNSEC3PARAMRecord();
            final ZoneHelper.HashData hd =
                    ZoneHelper.createInHashOrder(rrSetIds, nsec3Params,
                                                 parser.getCurrentDelegatedNSRecords(),
                                                 zoneName);
            final HashMap<String, String> nextNsec3Map =
                ZoneHelper.createNextNsec3Map(hd.getHashOrder(), nsec3Params);
            final String first = hd.getHashOrder().get(0).toString(false);

            // Key-pairs for ZSK1 and ZSK2
            final KeyPair zsk1KeyPair = new KeyPair(zskCryptoInstances.get(0).getPublicKey(), zskCryptoInstances.get(0).getPrivateKey());
            final PublicKey zsk2PublicKey = zskCryptoInstances.get(1).getPublicKey();
            final DNSKEYRecord dnskeyZSK1 = new DNSKEYRecord(Name.fromString(zoneName), DClass.IN, soa.getTTL(), DNSKEYRecord.Flags.ZONE_KEY, DNSKEYRecord.Protocol.DNSSEC, signatureAlgorithmDnssec, zsk1KeyPair.getPublic());
            final DNSKEYRecord dnskeyZSK2 = new DNSKEYRecord(Name.fromString(zoneName), DClass.IN, soa.getTTL(), DNSKEYRecord.Flags.ZONE_KEY, DNSKEYRecord.Protocol.DNSSEC, signatureAlgorithmDnssec, zsk2PublicKey);

            final DNSKEYRecord dnskeyZSK0;
            if (zskCryptoInstances.size() > 2) {
                final PublicKey zsk0PublicKey = zskCryptoInstances.get(2).getPublicKey();
                dnskeyZSK0 = new DNSKEYRecord(Name.fromString(zoneName), DClass.IN, soa.getTTL(), DNSKEYRecord.Flags.ZONE_KEY, DNSKEYRecord.Protocol.DNSSEC, signatureAlgorithmDnssec, zsk0PublicKey);
            } else {
                dnskeyZSK0 = null;
            }
            
            final List<DNSKEYRecord> ksks = new LinkedList<>();
            final RRset dnskeySet = new RRset();

            for (final ICryptoInstance kskCrypto : kskCryptoInstances) {
                final DNSKEYRecord dnskeyKSK = new DNSKEYRecord(Name.fromString(zoneName), DClass.IN, soa.getTTL(), 0x101, DNSKEYRecord.Protocol.DNSSEC, signatureAlgorithmDnssec, kskCrypto.getPublicKey());
                
                ksks.add(dnskeyKSK);
                dnskeySet.addRR(dnskeyKSK);
            }

            dnskeySet.addRR(dnskeyZSK1);
            dnskeySet.addRR(dnskeyZSK2);
            if (dnskeyZSK0 != null) {
                dnskeySet.addRR(dnskeyZSK0);
            }
            
            final List<RRSIGRecord> kskSigs = new LinkedList<>();
            
            for (final ICryptoInstance kskCrypto : kskCryptoInstances) {
                final DNSKEYRecord dnskeyKSK = new DNSKEYRecord(Name.fromString(zoneName), DClass.IN, soa.getTTL(), 0x101, DNSKEYRecord.Protocol.DNSSEC, signatureAlgorithmDnssec, kskCrypto.getPublicKey());
                
                final Record sigDnskeyKSK = DNSSEC.sign(dnskeySet, dnskeyKSK, kskCrypto.getPrivateKey(), timeSigned, expire);
                
                kskSigs.add((RRSIGRecord) sigDnskeyKSK);
            }
            
            final RRSIGRecord sigDnskeyZSK = DNSSEC.sign(dnskeySet, dnskeyZSK1, zsk1KeyPair.getPrivate(), timeSigned, expire);

            // TODO: make MIN_REMANINING configurable
            final Phase1Data d =
                    new Phase1Data(first, nextNsec3Map, hd, soa, dnskeyZSK0, dnskeyZSK1,
                                   dnskeyZSK2, ksks, kskSigs, sigDnskeyZSK,
                                   timeSigned, expire, nsec3Params, null,
                                   typesMap, rrSetIds, rrSetMap, parser,
                                   zoneName, null, null, ZoneHelper.MIN_REMAINING);
            
            //bigLoop(outputStream, d, zsk1KeyPair);
            final ZoneSignatureCreator sigCreator =
                    createSignatureCreator(d, zsk1KeyPair);
            ZoneHelper.bigLoop(outputStream, d, sigCreator);
            
        } finally {
            for (InputStream inputStream : inputStreamsToBeClosed) {
                inputStream.close();
            }
        }
    }

    protected abstract ZoneSignatureCreator createSignatureCreator(Phase1Data d,
                                                                   KeyPair zsk1KeyPair)
            throws IllegalRequestException;
        
    protected static int getZskSequenceNumber(RequestContext context) throws IllegalRequestException {
        final String zskSeqNum = RequestMetadata.getInstance(context).get(METADATA_ZSK_SEQUENCE_NUMBER);
        if (zskSeqNum == null) {
            throw new IllegalRequestException(METADATA_ZSK_SEQUENCE_NUMBER + " is not provided as part of request metadata");
        }

        try {
            return Integer.parseInt(zskSeqNum);
        } catch (NumberFormatException ex) {
            throw new IllegalRequestException("Illegal " + METADATA_ZSK_SEQUENCE_NUMBER + " provided", ex);
        }
    }

    /**
     * Extracts zone file from requestData (either input file or zip).
     *
     * @param requestData
     * @param zoneName
     * @return Parser holding zone file objects
     * @throws java.io.IOException
     * @throws org.signserver.common.IllegalRequestException
     */
    protected abstract ZoneFileParser extractZoneFileAndParse(ReadableData requestData, RequestContext requestContext, String zoneName, List<InputStream> inputStreamsToBeClosed) throws IOException, IllegalRequestException;

    private NSEC3PARAMRecord newNSEC3PARAMRecord() throws NoSuchAlgorithmException, TextParseException {
        // Create the salt
        final byte[] salt;
        if (decodedSalt == null) {
            if (random == null) {
                random = SecureRandom.getInstance(RANDOM_ALGORITHM);
            }
            salt = new byte[8];
            random.nextBytes(salt);
        } else {
            salt = decodedSalt;
        }
    
        return new NSEC3PARAMRecord(Name.fromString(zoneName),
                                         DClass.IN, 0, NSEC3Record.Digest.SHA1, 0, 10,
                                         salt);
    }

}
