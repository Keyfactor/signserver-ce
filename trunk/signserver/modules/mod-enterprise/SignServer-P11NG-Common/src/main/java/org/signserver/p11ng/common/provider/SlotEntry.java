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
