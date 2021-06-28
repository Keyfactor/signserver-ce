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
package org.signserver.test.utils.mock;

import org.signserver.server.entities.IKeyUsageCounterDataService;
import org.signserver.server.entities.KeyUsageCounter;

/**
 * Mockup version of the KeyUsageCounterService.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class KeyUsageCounterServiceMock implements IKeyUsageCounterDataService {

    @Override
    public void create(String keyHash) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public KeyUsageCounter getCounter(String keyHash) {
        return new KeyUsageCounter(keyHash, 42);
    }

    @Override
    public boolean incrementIfWithinLimit(String keyHash, long limit) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean isWithinLimit(String keyHash, long keyUsageLimit) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
}
