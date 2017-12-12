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
package org.signserver.server;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.pkcs11.jacknji11.CKM;
import org.signserver.server.cryptotokens.MechanismNames;

/**
 * This class contains mappings between Java algorithm names and corresponding constant value for JackNJ11 Provider.
 * @author Vinay Singh
 * @version $Id$
 */
public class KeyIdentifierUtils {
    
    public static final String CKM_SECRET_KEY_ALGO_SUFFIX="_KEY_GEN";

    private static final HashMap<Long, String> KNOWNSECRETKEYALGOL2S;
    private static final HashMap<String, Long> KNOWNSECRETKEYALGOS2L;

    private static final HashMap<Long, String> KNOWNPRIVATEKEYALGOL2S;
    private static final HashMap<String, Long> KNOWNPRIVATEKEYALGOS2L; 

    public static final List<String> KNOWNSECRETKEYALGOS2LMAPKEYS;
    public static final List<Long> KNOWNSECRETKEYALGOL2SMAPKEYS;

    public static final List<String> KNOWNPRIVATEKEYALGOS2LMAPKEYS;
    public static final List<Long> KNOWNPRIVATEKEYALGOL2SMAPKEYS;

    static {
        KNOWNSECRETKEYALGOS2L = new HashMap<>();
        KNOWNSECRETKEYALGOS2L.put("AES", CKM.AES_KEY_GEN);
        KNOWNSECRETKEYALGOS2L.put("DES", CKM.DES_KEY_GEN);
        KNOWNSECRETKEYALGOS2L.put("CAST128", CKM.CAST128_KEY_GEN);

        KNOWNPRIVATEKEYALGOS2L = new HashMap<>();
        KNOWNPRIVATEKEYALGOS2L.put("RSA", CKM.RSA_PKCS_KEY_PAIR_GEN);
        KNOWNPRIVATEKEYALGOS2L.put("DSA", CKM.DSA_KEY_PAIR_GEN);

        KNOWNPRIVATEKEYALGOL2S = new HashMap<>(KNOWNPRIVATEKEYALGOS2L.size());
        for (Map.Entry<String, Long> entry : KNOWNSECRETKEYALGOS2L.entrySet()) {
            KNOWNPRIVATEKEYALGOL2S.put(entry.getValue(), entry.getKey());
        }

        KNOWNSECRETKEYALGOL2S = new HashMap<>(KNOWNSECRETKEYALGOS2L.size());
        for (Map.Entry<String, Long> entry : KNOWNSECRETKEYALGOS2L.entrySet()) {
            KNOWNSECRETKEYALGOL2S.put(entry.getValue(), entry.getKey());
        }        

        KNOWNSECRETKEYALGOL2SMAPKEYS = new ArrayList(KNOWNSECRETKEYALGOL2S.keySet());
        KNOWNSECRETKEYALGOS2LMAPKEYS = new ArrayList(KNOWNSECRETKEYALGOS2L.keySet());

        KNOWNPRIVATEKEYALGOS2LMAPKEYS = new ArrayList(KNOWNPRIVATEKEYALGOS2L.keySet());
        KNOWNPRIVATEKEYALGOL2SMAPKEYS = new ArrayList(KNOWNPRIVATEKEYALGOL2S.keySet());
    }
    
    public static long getProviderAlgoValue(String algorithm) {
        String providerAlgoName = algorithm + CKM_SECRET_KEY_ALGO_SUFFIX;
        Long longValue = MechanismNames.longFromName(providerAlgoName);
        if (longValue != null) {
            return longValue;
        } else {
            throw new IllegalArgumentException("Secret Key Algorithm " + algorithm + " not supported ");
        }
    }             
}
