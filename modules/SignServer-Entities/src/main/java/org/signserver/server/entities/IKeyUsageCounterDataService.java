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
package org.signserver.server.entities;

/**
 * DataService managing the persistence of the key usage counter.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public interface IKeyUsageCounterDataService {

    /**
     * Create a new key usage counter entry for the given key hash
     * @param keyHash Hash of the key to create an entry for
     */
    void create(final String keyHash);

    /**
     * Get the current value of the key usage counter for the given key hash.
     * @param keyHash Hash of the key
     * @return The current key usage counter value
     */
    KeyUsageCounter getCounter(final String keyHash);

    /**
     * Increase the value of the key usage counter but only if the limit is not 
     * exceeded in which case it instead just returns false.
     * @param keyHash Hash of the key
     * @param limit The maximum number of operations
     * @return True if the counter was increased or false if the limit was 
     * exceeded or the counter not initialized
     */
    boolean incrementIfWithinLimit(String keyHash, long limit);

    /**
     * Checks if the counter for the given key is within the given limit.
     * @param keyHash Hash of the key
     * @param keyUsageLimit The maximum number of operations
     * @return True if the current value of the counter is less than the key 
     * usage limit
     */
    boolean isWithinLimit(String keyHash, long keyUsageLimit);
   
}
