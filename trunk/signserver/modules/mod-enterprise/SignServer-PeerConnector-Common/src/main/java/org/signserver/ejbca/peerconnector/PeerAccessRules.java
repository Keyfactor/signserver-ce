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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Peer Connector access rules.
 * @version $Id$
 */
public enum PeerAccessRules {
    INCOMING("/peerincoming"),
    BASE("/peer"),
    /** View */
    VIEW("/peer/view"),
    /** Create, delete and update */
    EDIT("/peer/modify"),
    /** Perform authorized operations on peer system */
    MANAGE("/peer/manage");
    
    private final String resource;
    
    private static final Map<String,String> allResources = new HashMap<>();
    
    static {
        for (final PeerAccessRules peerAccessRule : PeerAccessRules.values()) {
            allResources.put(peerAccessRule.getResource(), peerAccessRule.getResource());
        }
    }
    
    private PeerAccessRules(String resource) {
        this.resource = resource;
    }

    public String getResource() {
        return this.resource;
    }

    public String toString() {
        return this.resource;
    }
    
    public static Map<String,String> getAllResource() {  
        return Collections.unmodifiableMap(allResources);
    }
}
