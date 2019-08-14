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
package org.signserver.admin.web;

import java.text.Collator;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.util.StringTools;

/**
 * Utility methods for selecting key algorithms and specifications.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class KeyUtils {
    private static final int[] RSA_KEY_SIZES = {1024, 2048, 3072, 4096, 6144, 8192};
    private static final int[] DSA_KEY_SIZES = {1024};
    private static final int[] AES_KEY_SIZES = {128, 192, 256};
    private static final LinkedHashMap<String, String> ECDSA_CURVES;
    // list of curves to prioritize to the top of the selectable list for convenience
    private static final String[] PRIO_CURVES =
        {"prime256v1", "secp384r1", "secp521r1"};

    static {
        final Map<String, List<String>> namedEcCurvesMap =
                AlgorithmTools.getNamedEcCurvesMap(false);
        final Set<String> keys = namedEcCurvesMap.keySet();
        final String[] names = keys.toArray(new String[namedEcCurvesMap.size()]);
        final List<String> prioritizedCurves = Arrays.asList(PRIO_CURVES);

        ECDSA_CURVES = new LinkedHashMap<>();
        Arrays.sort(names, Collator.getInstance(Locale.ENGLISH));

        // insert prioritized curves at the top
        for (final String name : names) {
            if (prioritizedCurves.contains(name)) {
                ECDSA_CURVES.put(name, StringTools.getAsStringWithSeparator(" / ", namedEcCurvesMap.get(name)));
            }
        }

        // curves not in the prioritized
        for (final String name : names) {
            if (!prioritizedCurves.contains(name)) {
                ECDSA_CURVES.put(name, StringTools.getAsStringWithSeparator(" / ", namedEcCurvesMap.get(name)));
            }
        }
    }
    
    /**
     * Gets a map of algorithm labels and values (suitable for a bean
     * binding to a f:selectItems in an h:selectOneMenu).
     * 
     * @return The map of key algorithm labels and values.
     */
    public static Map<String, Object> getAlgorithmsMap() {
        final Map<String, Object> algMenuValues = new LinkedHashMap<>();

        algMenuValues.put("RSA", "RSA");
        algMenuValues.put("DSA", "DSA");
        algMenuValues.put("ECDSA", "ECDSA");
        algMenuValues.put("AES", "AES");

        return algMenuValues;
    }

    /**
     * Gets a map of key specification labels and values given a key algorithm
     * (suitable for a bean 
     * 
     * @param keyAlg
     * @return 
     */
    public static Map<String, Object> getKeySpecsMap(final String keyAlg) {
        final Map<String, Object> keySpecMenuValues = new LinkedHashMap<>();

        switch (keyAlg) {
            case "RSA":
                for (final int keySize : RSA_KEY_SIZES) {
                    keySpecMenuValues.put(Integer.toString(keySize),
                                          Integer.toString(keySize));
                }
                break;
            case "DSA":
                for (final int keySize : DSA_KEY_SIZES) {
                    keySpecMenuValues.put(Integer.toString(keySize),
                                          Integer.toString(keySize));
                }
                break;
            case "ECDSA":
                ECDSA_CURVES.keySet().forEach((key) -> {
                    keySpecMenuValues.put(ECDSA_CURVES.get(key), key);
                });
                break;

            case "AES":
                for (final int keySize : AES_KEY_SIZES) {
                    keySpecMenuValues.put(Integer.toString(keySize),
                                          Integer.toString(keySize));
                }
                break;
            default:
                // leave it blank
                break;
        }

        return keySpecMenuValues;
    }
}
