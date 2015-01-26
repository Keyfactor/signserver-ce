/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.server.cryptotokens;

import java.io.Serializable;
import java.util.List;

/**
 *
 * @author user
 */
public class TokenSearchResults implements Serializable {
    private final List<TokenEntry> entries;
    private final Boolean moreEntriesAvailable;
    private final Long moreEntries;

    public TokenSearchResults(List<TokenEntry> entries) {
        this.entries = entries;
        this.moreEntriesAvailable = null;
        this.moreEntries = null;
    }
    
    public TokenSearchResults(List<TokenEntry> entries, long moreEntries) {
        this.entries = entries;
        this.moreEntriesAvailable = moreEntries > 0;
        this.moreEntries = moreEntries;
    }
    
    public TokenSearchResults(List<TokenEntry> entries, boolean moreEntriesAvailable) {
        this.entries = entries;
        this.moreEntriesAvailable = moreEntriesAvailable;
        this.moreEntries = null;
    }

    public List<TokenEntry> getEntries() {
        return entries;
    }

    public Boolean isMoreEntriesAvailable() {
        return moreEntriesAvailable;
    }

    public Long getMoreEntries() {
        return moreEntries;
    }
    
}
