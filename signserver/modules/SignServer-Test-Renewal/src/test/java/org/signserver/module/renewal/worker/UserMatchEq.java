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
package org.signserver.module.renewal.worker;

import org.signserver.module.renewal.ejbcaws.gen.UserMatch;

/**
 * Adding the equals() and hashCode() methods to UserMatch.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class UserMatchEq extends UserMatch {

    public UserMatchEq() {
    }

    public UserMatchEq(UserMatch arg0) {
        matchtype = arg0.getMatchtype();
        matchvalue = arg0.getMatchvalue();
        matchwith = arg0.getMatchwith();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final UserMatchEq other = (UserMatchEq) obj;
        if (this.matchtype != other.matchtype) {
            return false;
        }
        if ((this.matchvalue == null) ? (other.matchvalue != null)
                : !this.matchvalue.equals(other.matchvalue)) {
            return false;
        }
        if (this.matchwith != other.matchwith) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 31 * hash + this.matchtype;
        hash = 31 * hash + (this.matchvalue != null
                ? this.matchvalue.hashCode() : 0);
        hash = 31 * hash + this.matchwith;
        return hash;
    }

}
