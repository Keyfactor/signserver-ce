/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.ades;

import java.util.EnumSet;
import java.util.Set;

/**
 * AdES Signature levels.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public enum AdESSignatureLevel {

    BASELINE_B,
    BASELINE_T,
    BASELINE_LT,
    BASELINE_LTA;

    /**
     * The subset of signature levels requiring timestamping.
     */
    public static Set<AdESSignatureLevel> TIMESTAMPING_REQUIRED =
            EnumSet.of(BASELINE_T, BASELINE_LT, BASELINE_LTA);

    /**
     * The subset of signature levels requiring revocation information.
     */
    public static Set<AdESSignatureLevel> REVOCATION_REQUIRED =
            EnumSet.of(BASELINE_LT, BASELINE_LTA);
    
    /**
     * Return the the level name based on the name, with dash, instead
     * of _ as in the enum values, e.g. BASELINE-B
     *
     * @param name of level
     * @return enum value corresponding to name
     */
    public static AdESSignatureLevel valueByName(final String name) {
        return valueOf(name.replace('-', '_'));
    }

    /**
     * Override to give level names of the form with - as in ETSI standards.
     * E.g. "BASELINE-B"
     *
     * @return The signature level name in ETSI form.
     */
    @Override
    public String toString() {
        return name().replace('_', '-');
    }
}
