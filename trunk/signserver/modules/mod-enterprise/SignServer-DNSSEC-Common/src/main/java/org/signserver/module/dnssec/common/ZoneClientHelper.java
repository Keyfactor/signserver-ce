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

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import org.apache.log4j.Logger;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.NSEC3PARAMRecord;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.SOARecord;

/**
 * Utility methods for client-side zone file hashing and construction.
 * 
 * @author Marcus Lundblad
 * @author Markus Kilås
 * @version $Id$
 */
public class ZoneClientHelper {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ZoneClientHelper.class);
    
    public static class TbsRecord {
        private final RRSIGRecord sigRecord;
        private final RRset rrset;

        public TbsRecord(RRSIGRecord sigRecord, RRset rrset) {
            this.sigRecord = sigRecord;
            this.rrset = rrset;
        }

        public RRSIGRecord getSigRecord() {
            return sigRecord;
        }

        public RRset getRrset() {
            return rrset;
        }

        @Override
        public int hashCode() {
            int hash = 7;
            hash = 53 * hash + Objects.hashCode(this.sigRecord);
            hash = 53 * hash + Objects.hashCode(this.rrset);
            return hash;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            final TbsRecord other = (TbsRecord) obj;
            if (!Objects.equals(this.sigRecord, other.sigRecord)) {
                return false;
            }

            return Objects.equals(this.rrset, other.rrset);
        }
    }
    
    public static class Phase1Data {
        private final String first;
        private HashMap<String, String> nextNsec3Map;
        private final ZoneHelper.HashData hd;
        private final SOARecord soa;
        private final DNSKEYRecord dnskeyZSK0;
        private final DNSKEYRecord dnskeyZSK1;
        private final DNSKEYRecord dnskeyZSK2;
        private final List<DNSKEYRecord> ksks;
        private final List<RRSIGRecord> kskSigs;
        private final RRSIGRecord sigDnskeyZSK;
        private final Date timeSigned;
        private final Date expire;
        private final NSEC3PARAMRecord nsec3Params;
        private final RRSIGRecord nsec3ParamsSig;
        private final HashMap<String, List<Integer>> typesMap;
        private final ArrayList<RRsetId> rrSetIds;
        private final HashMap<RRsetId, RRset> rrSetMap;
        private final ZoneFileParser parser;
        private final String zoneName;
        private final HashMap<String, TbsRecord> sigMap;
        private final HashMap<RRsetId, String> rrsetId2sigId;
        private final Long minRemainingValidity;

        public Phase1Data(String first, HashMap<String, String> nextNsec3Map, ZoneHelper.HashData hd, SOARecord soa, DNSKEYRecord dnskeyZSK0, DNSKEYRecord dnskeyZSK1, DNSKEYRecord dnskeyZSK2, List<DNSKEYRecord> ksks, List<RRSIGRecord> kskSigs, RRSIGRecord sigDnskeyZSK, Date timeSigned, Date expire, NSEC3PARAMRecord nsec3Params, RRSIGRecord nsec3ParamsSig, HashMap<String, List<Integer>> typesMap, ArrayList<RRsetId> rrSetIds, HashMap<RRsetId, RRset> rrSetMap, ZoneFileParser parser, String zoneName, HashMap<String, TbsRecord> sigMap, HashMap<RRsetId, String> rrsetId2sigId, Long minRemainingValidity) {
            this.first = first;
            this.nextNsec3Map = nextNsec3Map;
            this.hd = hd;
            this.soa = soa;
            this.dnskeyZSK0 = dnskeyZSK0;
            this.dnskeyZSK1 = dnskeyZSK1;
            this.dnskeyZSK2 = dnskeyZSK2;
            this.ksks = ksks;
            this.kskSigs = kskSigs;
            this.sigDnskeyZSK = sigDnskeyZSK;
            this.timeSigned = timeSigned;
            this.expire = expire;
            this.nsec3Params = nsec3Params;
            this.nsec3ParamsSig = nsec3ParamsSig;
            this.typesMap = typesMap;
            this.rrSetIds = rrSetIds;
            this.rrSetMap = rrSetMap;
            this.parser = parser;
            this.zoneName = zoneName;
            this.sigMap = sigMap;
            this.rrsetId2sigId = rrsetId2sigId;
            this.minRemainingValidity = minRemainingValidity;
        }

        public String getFirst() {
            return first;
        }

        public HashMap<String, String> getNextNsec3Map() {
            return nextNsec3Map;
        }

        public void setNextNsec3Map(HashMap<String, String> nextNsec3Map) {
            this.nextNsec3Map = nextNsec3Map;
        }

        public ZoneHelper.HashData getHd() {
            return hd;
        }

        public SOARecord getSoa() {
            return soa;
        }

        public DNSKEYRecord getDnskeyZSK0() {
            return dnskeyZSK0;
        }

        public DNSKEYRecord getDnskeyZSK1() {
            return dnskeyZSK1;
        }

        public DNSKEYRecord getDnskeyZSK2() {
            return dnskeyZSK2;
        }

        public List<DNSKEYRecord> getKsks() {
            return ksks;
        }

        public List<RRSIGRecord> getKskSigs() {
            return kskSigs;
        }

        public RRSIGRecord getSigDnskeyZSK() {
            return sigDnskeyZSK;
        }

        public Date getTimeSigned() {
            return timeSigned;
        }

        public Date getExpire() {
            return expire;
        }

        public NSEC3PARAMRecord getNsec3Params() {
            return nsec3Params;
        }

        public RRSIGRecord getNsec3ParamsSig() {
            return nsec3ParamsSig;
        }

        public HashMap<String, List<Integer>> getTypesMap() {
            return typesMap;
        }

        public ArrayList<RRsetId> getRrSetIds() {
            return rrSetIds;
        }

        public HashMap<RRsetId, RRset> getRrSetMap() {
            return rrSetMap;
        }

        public ZoneFileParser getParser() {
            return parser;
        }

        public String getZoneName() {
            return zoneName;
        }

        public HashMap<String, TbsRecord> getSigMap() {
            return sigMap;
        }

        public HashMap<RRsetId, String> getRrsetId2sigId() {
            return rrsetId2sigId;
        }   
    }
}
