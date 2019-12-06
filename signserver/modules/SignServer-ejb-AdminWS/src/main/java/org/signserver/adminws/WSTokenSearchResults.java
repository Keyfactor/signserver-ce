/*************************************************************************
 *                                                                       *
 *  SignServer: The OpenSource Automated Signing Server                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.adminws;

import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlType;
import org.signserver.server.cryptotokens.TokenEntry;
import org.signserver.server.cryptotokens.TokenSearchResults;

/**
 * WS version of TokenSearchResults.
 *
 * @author Markus Kilås
 * @version $Id$
 * @see TokenSearchResults
 */
@XmlType(name = "tokenSearchResults")
public class WSTokenSearchResults {
  
    private List<WSTokenEntry> entries;
    private Boolean moreEntriesAvailable;
    private Long numMoreEntries;

    /**
     * Converts a TokenSearchResults to a WSTokenSearchResults.
     * @param src the TokenSearchResults
     * @return the WSTokenSearchResults
     */
    public static WSTokenSearchResults fromTokenSearchResults(final TokenSearchResults src) {
        final List<WSTokenEntry> entries = new LinkedList<>();
        for (TokenEntry entry : src.getEntries()) {
            entries.add(WSTokenEntry.fromTokenEntry(entry));
        }
        return new WSTokenSearchResults(entries, src.isMoreEntriesAvailable(), src.getNumMoreEntries());
    }

    /** Default no-arg constructor. */
    public WSTokenSearchResults() {
    }

    public WSTokenSearchResults(List<WSTokenEntry> entries, Boolean moreEntriesAvailable, Long numMoreEntries) {
        this.entries = entries;
        this.moreEntriesAvailable = moreEntriesAvailable;
        this.numMoreEntries = numMoreEntries;
    }

    public List<WSTokenEntry> getEntries() {
        return entries;
    }

    public Boolean isMoreEntriesAvailable() {
        return moreEntriesAvailable;
    }

    public Long getNumMoreEntries() {
        return numMoreEntries;
    }

    public void setMoreEntriesAvailable(Boolean moreEntriesAvailable) {
        this.moreEntriesAvailable = moreEntriesAvailable;
    }

    public void setEntries(List<WSTokenEntry> entries) {
        this.entries = entries;
    }

    public void setNumMoreEntries(Long numMoreEntries) {
        this.numMoreEntries = numMoreEntries;
    }
   
}
