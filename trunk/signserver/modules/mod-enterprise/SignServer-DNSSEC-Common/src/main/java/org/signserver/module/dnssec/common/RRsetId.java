/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.dnssec.common;

import java.util.Objects;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Type;

/**
 * Representing the Id of an RRset.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class RRsetId {
    
    private final Name name;
    private final int type;
    private final int dClass;

    public RRsetId(Name name, int type, int dClass) {
        this.name = name;
        this.type = type;
        this.dClass = dClass;
    }

    public static RRsetId fromRecord(Record r) {
        return new RRsetId(r.getName(), r.getRRsetType(), r.getDClass());
    }

    public Name getName() {
        return name;
    }

    public int getType() {
        return type;
    }

    public int getdClass() {
        return dClass;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 43 * hash + Objects.hashCode(this.name);
        hash = 43 * hash + this.type;
        hash = 43 * hash + this.dClass;
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final RRsetId other = (RRsetId) obj;
        if (this.type != other.type) {
            return false;
        }
        if (this.dClass != other.dClass) {
            return false;
        }
        if (!Objects.equals(this.name, other.name)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "RRsetId{" + name + ", " + Type.string(type) + ", " + DClass.string(dClass) + '}';
    }
    
}
