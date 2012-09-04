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
     * Entity Bean holding info about a workers (service or signer) configuration
     *
     * @param workerId uniqe Id of the worker
     *
     */
    void create(final String keyHash);

    KeyUsageCounter getCounter(final String keyHash);

    boolean incrementIfWithinLimit(String keyHash, long limit);

    public boolean isWithinLimit(String keyHash, long keyUsageLimit);
   
}
