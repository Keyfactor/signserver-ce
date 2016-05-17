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

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import org.signserver.common.RequestContext;

/**
 * Holder for acquired crypto instance stored in the RequestContext.
 *
 * @see RequestContext
 * @author Markus Kilås
 * @version $Id$
 */
public class CryptoInstances {
    
    private static final String REQUESTCONTEXT_KEY = "CRYPTO_INSTANCES";
    
    private final Set<ICryptoInstance> instances = new HashSet<>();
    
    /**
     * Get the CryptoInstances from the RequestContext or create and put a new 
     * one if it does not exist yet.
     * @param requestContext The request context for the transaction
     * @return An CryptoInstances instance now existing in the RequestContext
     */
    public static CryptoInstances getInstance(final RequestContext requestContext) {
        final CryptoInstances result;
        final Object o = requestContext.get(REQUESTCONTEXT_KEY);
        if (o instanceof CryptoInstances) {
            result = (CryptoInstances) o;
        } else {
            result = new CryptoInstances();
            requestContext.put(REQUESTCONTEXT_KEY, result);
        }
        return result;
    }
    
    /**
     * Add an new ICryptoInstance to this holder.
     * @param instance to add
     * @return True if the instance did not already exist
     */
    public boolean add(ICryptoInstance instance) {
        return instances.add(instance);
    }
    
    /**
     * Remove an ICryptoInstance from this holder.
     * @param instance to remove
     * @return If the instance existed
     */
    public boolean remove(ICryptoInstance instance) {
        return instances.remove(instance);
    }
    
    /**
     * @return An unmodifiable view of all the instances in this holder
     */
    public Collection<ICryptoInstance> getAll() {
        return Collections.unmodifiableSet(instances);
    }
}
