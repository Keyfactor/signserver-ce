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
package org.signserver.server.cryptotokens;

import java.util.HashMap;
import java.util.Map;
import org.pkcs11.jacknji11.C;
import org.pkcs11.jacknji11.CKA;

/**
 * Handles mapping between PKCS#11 attribute constant names and values.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class AttributeNames {

    private static final Map<Long, String> L2S = C.createL2SMap(CKA.class);
    private static final Map<String, Long> S2L;

    static {
        S2L = new HashMap<>(L2S.size());
        for (Map.Entry<Long, String> entry : L2S.entrySet()) {
            S2L.put(entry.getValue(), entry.getKey());
        }
    }

    /**
     * Convert long constant value to name.
     * @param l constant value
     * @return name of constant or hexadecimal value if unknown
     */
    public static String nameFromLong(long l) {
        String s = L2S.get(l);
        if (s == null) {
            return String.format("0x%08x", l);
        } else {
            return s;
        }
    }

    /**
     * The the long value from the name.
     * @param name to get long value for
     * @return long value or null if unknown
     */
    public static Long longFromName(String name) {
        return S2L.get(name);
    }
}
