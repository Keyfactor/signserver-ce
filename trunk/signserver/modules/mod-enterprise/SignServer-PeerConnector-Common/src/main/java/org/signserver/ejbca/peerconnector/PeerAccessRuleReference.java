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

import java.util.Map;

import org.cesecore.authorization.rules.AccessRulePlugin;

/**
 * Reference class for a rule enum, which can't be instantiated. 
 * 
 * @version $Id$
 */
public class PeerAccessRuleReference implements AccessRulePlugin {
    
    @Override
    public Map<String,String> getRules() {
        return PeerAccessRules.getAllResource();
    }
    
    @Override
    public String getCategory() {
        return "PEERMANAGEMENTRULES";
    }
}
