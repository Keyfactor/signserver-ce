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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import org.xbill.DNS.Master;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.Type;

/**
 * Parser for zone file Master objects.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ZoneFileParser {
    private Master current;
    private Master previous;

    private final HashMap<RRsetId, RRset> currentRrSetMap = new HashMap<>();
    private final HashMap<RRsetId, RRset> previousRrSetMap = new HashMap<>();
    private final ArrayList<RRsetId> currentRrSetIds = new ArrayList<>();
    private final ArrayList<RRsetId> previousRrSetIds = new ArrayList<>();
    private final HashMap<RRsetId, RRSIGRecord> currentRrSigMap = new HashMap<>();    
    private final HashMap<RRsetId, RRSIGRecord> previousRrSigMap = new HashMap<>();
    private ArrayList<RRsetId> reusableRrSetIds = new ArrayList<>();
    private final ArrayList<RRsetId> newRrSetIds = new ArrayList<>();
    private final HashMap<RRsetId, RRset> reusableRrSetMap = new HashMap<>();
    private final HashMap<RRsetId, RRset> newRrSetMap = new HashMap<>();
    private SOARecord currentSoa;
    private SOARecord previousSoa;
    private final ArrayList<Record> currentDelegatedNSRecords = new ArrayList<>();
    private final ArrayList<Record> previousDelegatedNSRecords = new ArrayList<>();

    /**
     * Create a new zone file parser given a current zone file
     * and optionally an upcoming zone file.
     * 
     * @param current The current zone file
     * @param previous The previous zone file, or null there is no previous
     * @param forceSign
     * @throws java.io.IOException
     */
    public ZoneFileParser(final Master current, final Master previous, final boolean forceSign) throws IOException {
        this.current = current;
        this.previous = previous;

        parseCurrent();
        
        if (previous != null && !forceSign) {
            /* if forceSign flag is false and a previous zone is given, 
             *  then compare current and previous zone files to extract which records to be signed or 
             * which to be reused.
             */
            parsePrevious();            
            compareNewAndPrevRRSets();
        }
    }

    /**
     * Create a new zone file parser given a current zone file.
     *
     * @param current The current zone file
     * @throws IOException 
     */
    public ZoneFileParser(final Master current) throws IOException {
        this(current, null, true);
    }

    
    /**
     * Get a map from unique identiers to RRSets for the current zone file.
     * 
     * @return
     * @throws IOException 
     */
    public HashMap<RRsetId, RRset> getCurrentRrSetMap() throws IOException {
        return currentRrSetMap;
    }

    /**
     * Get a list of unique identifiers for RRSets for the current zone file.
     *
     * @return
     * @throws IOException 
     */
    public ArrayList<RRsetId> getCurrentRrSetIds() throws IOException {
        return currentRrSetIds;
    }
 
    /**
     * Get a list of delegated NS records for the current zone file.
     *
     * @return
     * @throws IOException 
     */
    public ArrayList<Record> getCurrentDelegatedNSRecords() throws IOException {
        return currentDelegatedNSRecords;
    }

    /**
     * Get a list of delegated NS records for the previous zone file.
     *
     * @return
     * @throws IOException 
     */
    private ArrayList<Record> getPreviousDelegatedNSRecords() throws IOException {
        return previousDelegatedNSRecords;
    }

    /**
     * Calculates reusable and new RRSets.
     * This is to be called after parsing current and previous zone files.
     *
     * @throws IOException 
     */
    private void compareNewAndPrevRRSets() throws IOException {
        if (currentRrSetIds.equals(previousRrSetIds)) {
            // worst case when all RRSetIds are same in current and prev zone file
            reusableRrSetIds = currentRrSetIds;
        } else {
            for (RRsetId rrSetId : currentRrSetIds) {
                if (previousRrSetIds.contains(rrSetId)) {
                    reusableRrSetIds.add(rrSetId);
                } else {
                    newRrSetIds.add(rrSetId);
                }
            }
        }
        
        checkRRSetsForMatchedRRSetIds(reusableRrSetIds, newRrSetIds);
        
        for(RRsetId rrSetId : reusableRrSetIds) {
            reusableRrSetMap.put(rrSetId, previousRrSetMap.get(rrSetId));
        }
        
        for(RRsetId rrSetId : newRrSetIds) {
            newRrSetMap.put(rrSetId, currentRrSetMap.get(rrSetId));
        }
        
    }

    private void checkRRSetsForMatchedRRSetIds(ArrayList<RRsetId> reusableRrSetIds, ArrayList<RRsetId> newRrSetIds) {
        Iterator<RRsetId> it = reusableRrSetIds.iterator();
        while (it.hasNext()) {
            RRsetId rrSetId = it.next();
            boolean RRSetMached = RRSetsEquals(currentRrSetMap.get(rrSetId), previousRrSetMap.get(rrSetId));
            if (!RRSetMached) {
                newRrSetIds.add(rrSetId);
                // remove from reusableRrSetIds
                it.remove();
            }
        }
    }
    
    private boolean RRSetsEquals(RRset newRRset, RRset prevRRset) {
        if (newRRset.size() != prevRRset.size()) {
            return false;
        } else {
            Iterator iterNewRRset = newRRset.rrs();
            Iterator iterPrevRRset = prevRRset.rrs();
            final List<Record> newRecords = new ArrayList<>();
            final List<Record> prevRecords = new ArrayList<>();

            while (iterNewRRset.hasNext()) {
                // Assuming same order of Records in both newRRset & prevRRset
                Record rInNewRRSet = (Record) iterNewRRset.next();
                Record rInPrevRRSet = (Record) iterPrevRRset.next();

                newRecords.add(rInNewRRSet);
                prevRecords.add(rInPrevRRSet);
            }
            
            Collections.sort(newRecords);
            Collections.sort(prevRecords);

            for (int i = 0; i < newRecords.size(); i++) {
                final Record rInNewRRSet = newRecords.get(i);
                final Record rInPrevRRSet = prevRecords.get(i);
                boolean sameRecord = rInNewRRSet.equals(rInPrevRRSet);
                if (!sameRecord) {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * Get the SOA record for the current zone file.
     *
     * @return
     * @throws IOException 
     */
    public SOARecord getCurrentSoa() throws IOException {
        return currentSoa;
    }

    /**
     * Get the SOA record for the previous zone file.
     *
     * @return
     * @throws IOException 
     */
    public SOARecord getPreviousSoa() throws IOException {
        return previousSoa;
    }

    private void parseCurrent() throws IOException {
        currentSoa = parseMaster(current, currentRrSetMap, currentRrSetIds,
                                 currentRrSigMap, currentDelegatedNSRecords);
    }

    private void parsePrevious() throws IOException {
        previousSoa =
                parseMaster(previous, previousRrSetMap, previousRrSetIds,
                            previousRrSigMap, previousDelegatedNSRecords);
    }

    private SOARecord parseMaster(final Master master,
                             final HashMap<RRsetId, RRset> rrSetMap,
                             final ArrayList<RRsetId> rrSetIds,
                             final HashMap<RRsetId, RRSIGRecord> sigMap,
                             final ArrayList<Record> delegatedNSRecords) throws IOException {
        SOARecord soa = null;
        
        while (true) {
            final Record record = master.nextRecord();

            if (record == null) {
                break;
            }

            // Put the record in the map and the list
            final RRsetId setId = RRsetId.fromRecord(record);

            if (soa == null && record instanceof SOARecord) {
                soa = (SOARecord) record;
            } else if (record instanceof RRSIGRecord) {
                final RRSIGRecord sigRecord = (RRSIGRecord) record;

                sigMap.put(setId, sigRecord);
            }

            if (record.getType() == Type.NS) {
                delegatedNSRecords.add(record);
            }

            // LOG.debug(record);

            RRset rrSet = rrSetMap.get(setId);
            if (rrSet == null) {
                rrSet = new RRset();
                rrSetMap.put(setId, rrSet);
                rrSetIds.add(setId);
            }
            rrSet.addRR(record);
        }

        if (soa != null) {
            final Name soaName = soa.getName();

            delegatedNSRecords.removeIf(r -> r.getName().equals(soaName));
        }

        return soa;
    }

    /**
     * Get a list of potentially reusable RRSets.
     * These records would be reused, if force-resign is not desired, and
     * their signature has enough remaining validity.
     * 
     * @return 
     */
    public ArrayList<RRsetId> getReusableRrSetIds() {
        return reusableRrSetIds;
    }

    /**
     * Get a list of new RRSets in the current zone file, not present in the
     * previous.
     *
     * @return 
     */
    public ArrayList<RRsetId> getNewRrSetIds() {
        return newRrSetIds;
    }

    /**
     * Get a map of the potentially reusable RRSets from unique identifier
     * to the RRSet instance.
     * 
     * @return 
     */
    public HashMap<RRsetId, RRset> getReusableRrSetMap() {
        return reusableRrSetMap;
    }

    /**
     * Get a map of the new RRSets in the current zone file from unique
     * identifier to the RRSet instance.
     *
     * @return 
     */
    public HashMap<RRsetId, RRset> getNewRrSetMap() {
        return newRrSetMap;
    }

    /**
     * Get the RRSIGRecord for a reusable RRSet identifier.
     * 
     * @param id Identifier of the RRSet
     * @return 
     */
    public RRSIGRecord getReusableSignatureForRrSet(RRsetId id) {
        final RRset set = reusableRrSetMap.get(id);
        
        if (set != null) {
            return previousRrSigMap.get(id);
        } else {
            return null;
        }
    }
}
