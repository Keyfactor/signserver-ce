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

import java.security.KeyStoreException;
import java.util.Arrays;
import java.util.LinkedList;
import org.apache.log4j.Logger;
import org.cesecore.util.query.QueryCriteria;
import static org.junit.Assert.*;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.SignServerException;
import org.signserver.testutils.ModulesTestCase;

/**
 * Generic CryptoToken tests. This class can be extended and the abstract
 * methods implemented to test a specific CryptoToken implementation.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public abstract class CryptoTokenTestBase extends ModulesTestCase {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(CryptoTokenTestBase.class);
    
    protected abstract TokenSearchResults searchTokenEntries(final int startIndex, final int max, final QueryCriteria criteria) 
            throws CryptoTokenOfflineException, KeyStoreException, InvalidWorkerIdException, SignServerException;
    
    protected abstract void generateKey(String keyType, String keySpec, String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, SignServerException;
    protected abstract boolean destroyKey(String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, SignServerException, KeyStoreException;
    
    /**
     * TODO tests...
     * 
     * Checks that the entries are returned in the same order for each call (given no entries added or removed).
     * @param existingKey
     * @throws Exception 
     */
    protected void searchTokenEntriesHelper(final String existingKey) throws Exception {
        
        final String[] testAliases = new String[] { "alias-14", "alias-13", "alias-5", "alias-10", "alias-2", "alias-1" };
        
        try {
            // First it is empty
            TokenSearchResults searchResults = searchTokenEntries(0, Integer.MAX_VALUE, QueryCriteria.create());
            LinkedList<String> aliases = new LinkedList<String>();
            for (TokenEntry entry : searchResults.getEntries()) {
                aliases.add(entry.getAlias());
            }
            LOG.info("Existing aliases: " + aliases);
            assertEquals("no entries except the test key yet", 1, searchResults.getEntries().size());
            assertFalse("no more entries", searchResults.isMoreEntriesAvailable());

            // Now create some entries
            for (String alias : testAliases) {
                generateKey("RSA", "1024", alias);
            }

            searchResults = searchTokenEntries(0, Integer.MAX_VALUE, QueryCriteria.create());
            aliases = new LinkedList<String>();
            for (TokenEntry entry : searchResults.getEntries()) {
                aliases.add(entry.getAlias());
            }
            
            // Check that all aliases are there
            for (String alias : testAliases) {
                assertTrue("should contain " + alias + " but only had " + aliases,
                        aliases.contains(alias));
            }
            assertTrue("should contain " + existingKey + " but only had " + aliases,
                        aliases.contains(existingKey));
            assertEquals("no more aliases than the expected in " + aliases,
                    testAliases.length + 1, aliases.size());
            
            final String[] allAliases = aliases.toArray(new String[0]);
            LOG.info("allAliases: " + Arrays.toString(allAliases));

            // Search 1 at the time
            searchResults = searchTokenEntries(0, 1, QueryCriteria.create());
            aliases = new LinkedList<String>();
            for (TokenEntry entry : searchResults.getEntries()) {
                aliases.add(entry.getAlias());
            }
            assertArrayEquals(new String[] { allAliases[0] }, aliases.toArray());
            assertTrue("more entries available", searchResults.isMoreEntriesAvailable());

            // Search 1 at the time
            searchResults = searchTokenEntries(1, 1, QueryCriteria.create());
            aliases = new LinkedList<String>();
            for (TokenEntry entry : searchResults.getEntries()) {
                aliases.add(entry.getAlias());
            }
            assertArrayEquals(new String[] { allAliases[1] }, aliases.toArray());
            assertTrue("more entries available", searchResults.isMoreEntriesAvailable());

            // Search 4 at the time, and then there are no more
            searchResults = searchTokenEntries(2, 5, QueryCriteria.create());
            aliases = new LinkedList<String>();
            for (TokenEntry entry : searchResults.getEntries()) {
                aliases.add(entry.getAlias());
            }
            assertArrayEquals(new String[] { allAliases[2], allAliases[3], allAliases[4], allAliases[5], allAliases[6] }, aliases.toArray());
            assertFalse("no more entries available", searchResults.isMoreEntriesAvailable());

            // Querying out of index returns empty results
            searchResults = searchTokenEntries(7, 1, QueryCriteria.create());
            aliases = new LinkedList<String>();
            for (TokenEntry entry : searchResults.getEntries()) {
                aliases.add(entry.getAlias());
            }
            assertArrayEquals(new String[] {}, aliases.toArray());
            assertFalse("no more entries available", searchResults.isMoreEntriesAvailable());
        } finally {
            for (String alias : testAliases) {
                try {
                    destroyKey(alias);
                } catch (Exception ex) {
                    LOG.error("Failed to remove alias: " + alias + ": " + ex.getLocalizedMessage());
                }
            }
        }
    }
    
}
