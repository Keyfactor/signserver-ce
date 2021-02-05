/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.apk.common;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.signserver.common.SignServerException;

/**
 * Utility methods for APK signing.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ApkUtils {

    // TODO: this is copied from JArchiveSigner, should probably be shared…
    /**
     * Convert the input string so that it is maximum 8 characters from 
     * 'A-Z0-9_- and minimum one character. Other characters are converted to
     * underscore and empty String converted to one underscore.
     *
     * @param signatureNameValue to convert
     * @return the converted String
     */
    public static String convertToValidSignatureName(String signatureNameValue) {
        String result;
        if (signatureNameValue.isEmpty()) {
            // Special case for empty
            result = "_";
        } else {
            // Convert to upper case, note we only allow A-Z so English locale should be fine
            signatureNameValue = signatureNameValue.toUpperCase(Locale.ENGLISH);

            // Truncate if needed
            if (signatureNameValue.length() > 8) {
                result = signatureNameValue.substring(0, 8);
            } else {
                result = signatureNameValue;
            }

            // Replace other characters
            result = result.replaceAll("[^a-zA-Z0-9_.-]", "_"); // TODO: Performance replace with static pattern matcher
        }

        return result;
    }

    /**
     * Get a name based on the wanted name but possibly truncated by a nummeric value so that
     * it is unique within then existingNames set.
     * @param wantedName to base the name on
     * @param existingNames from previous runs. Will be updated with the resulting name.
     * @return the new unique name that is also added to existingNames
     * @throws SignServerException in case 8 characters is not enough to find a unique name
     */
    public static String createUniqueSignatureFileName(String wantedName, Set<String> existingNames) throws SignServerException {
        String result;
        if (existingNames.add(wantedName)) {
            result = wantedName;
        } else {
            
            // XXX: There must be a better way than this
            int counter = 2;
            do {
                if ((wantedName + counter).length() > 8) {
                    result = wantedName.substring(0, 8 - String.valueOf(counter).length()) + String.valueOf(counter);
                } else {
                    result = wantedName + String.valueOf(counter);
                }
                if (String.valueOf(++counter).length() >= 8) {
                    throw new SignServerException("Unable to create unique signature file name");
                }
            } while (!existingNames.add(result));
        }
        return result;
    }

    public static List<X509Certificate> toX509List(List<Certificate> signingCertificateChain) {
        final List<X509Certificate> result = new ArrayList<>(signingCertificateChain.size());
        signingCertificateChain.forEach((c) -> {
            result.add((X509Certificate) c);
        });
        return result;
    }
}
