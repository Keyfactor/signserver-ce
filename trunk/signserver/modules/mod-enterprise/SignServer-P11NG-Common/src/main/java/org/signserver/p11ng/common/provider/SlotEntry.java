/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.p11ng.common.provider;

/**
 * Represents an entry in the HSM Slot with an alias and a type.
 *
 * @author Vinay Singh
 * @version $Id$
 */
public class SlotEntry {

    private final String alias;
    private final String type;

    public SlotEntry(String alias, String type) {
        this.alias = alias;
        this.type = type;
    }

    public String getType() {
        return this.type;
    }

    public String getAlias() {
        return this.alias;
    }    
}
