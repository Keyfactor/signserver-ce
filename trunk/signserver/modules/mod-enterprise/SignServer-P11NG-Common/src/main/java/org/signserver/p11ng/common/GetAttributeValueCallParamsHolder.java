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
package org.signserver.p11ng.common;

import java.util.Objects;

/**
 * Holder for parameters of getAttributeValue method HSM calls with respect to P11NG provider.
 * 
 * @author Vinay Singh
 * @version $Id$
 */
public class GetAttributeValueCallParamsHolder {

    private final long object;
    private final String paramName;

    public GetAttributeValueCallParamsHolder(long object, String paramName) {
        this.object = object;
        this.paramName = paramName;
    }

    public long getObject() {
        return object;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 89 * hash + (int) (this.object ^ (this.object >>> 32));
        hash = 89 * hash + Objects.hashCode(this.paramName);
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
        final GetAttributeValueCallParamsHolder other = (GetAttributeValueCallParamsHolder) obj;
        if (this.object != other.object) {
            return false;
        }
        if (!Objects.equals(this.paramName, other.paramName)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "GetAttributeValueCallParamsHolder{" + "object=" + object + ", paramName=" + paramName + '}';
    }

}
