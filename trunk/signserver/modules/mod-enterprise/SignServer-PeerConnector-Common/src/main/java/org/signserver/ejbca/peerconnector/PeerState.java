/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.ejbca.peerconnector;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 * @version $Id$
 *
 */
public enum PeerState implements Serializable {
    DISABLED(0), ENABLED(1);

    private static Map<Integer, PeerState> lookupMap = new HashMap<Integer, PeerState>();

    static {
        lookupMap = new HashMap<Integer, PeerState>();
        for(PeerState pperState : PeerState.values()) {
            lookupMap.put(pperState.getIntegerValue(), pperState);
        }
    }
    
    private int integerValue;

    private PeerState(int integerValue) {
        this.integerValue = integerValue;
    }
    
    public int getIntegerValue() {
        return integerValue;
    }
    
    public boolean isEnabled() {
        return integerValue == 1;
    }
    
    public static PeerState fromIntegerValue(int integerValue) {
        return lookupMap.get(integerValue);
    }
}
