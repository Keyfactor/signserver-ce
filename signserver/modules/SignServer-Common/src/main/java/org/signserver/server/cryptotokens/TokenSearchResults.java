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
package org.signserver.server.cryptotokens;

import java.io.Serializable;
import java.util.List;

/**
 * Results of a token entries search.
 * Contains a list of token entries and if available, information about
 * if there are more entries and how many (if information is available).
 * @author Markus Kilås
 * @version $Id$
 */
public class TokenSearchResults implements Serializable {
    private final List<TokenEntry> entries;
    private final Boolean moreEntriesAvailable;
    private final Long numMoreEntries;

    public TokenSearchResults(List<TokenEntry> entries) {
        this.entries = entries;
        this.moreEntriesAvailable = null;
        this.numMoreEntries = null;
    }
    
    public TokenSearchResults(List<TokenEntry> entries, long numMoreEntries) {
        this.entries = entries;
        this.moreEntriesAvailable = numMoreEntries > 0;
        this.numMoreEntries = numMoreEntries;
    }
    
    public TokenSearchResults(List<TokenEntry> entries, boolean moreEntriesAvailable) {
        this.entries = entries;
        this.moreEntriesAvailable = moreEntriesAvailable;
        this.numMoreEntries = null;
    }

    public List<TokenEntry> getEntries() {
        return entries;
    }

    public Boolean isMoreEntriesAvailable() {
        return moreEntriesAvailable;
    }

    public Long getNumMoreEntries() {
        return numMoreEntries;
    }
    
}
