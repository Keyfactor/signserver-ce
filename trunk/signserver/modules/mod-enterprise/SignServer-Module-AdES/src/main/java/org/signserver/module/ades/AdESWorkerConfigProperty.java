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

import org.signserver.common.worker.WorkerConfigProperty;

/**
 * Class containing the collection of configuration properties for an AdES worker.
 *
 * @author Andrey Sergeev
 * @version $Id$
 */
public class AdESWorkerConfigProperty extends WorkerConfigProperty {

    /**
     * AdES signature format property. Reflects values: PAdES, XAdES.
     */
    public static final String SIGNATURE_FORMAT = "SIGNATURE_FORMAT";

    /**
     * AdES signature packaging. Reflects values: DETACHED, ENVELOPED, ENVELOPING, INTERNALLY_DETACHED.
     */
    public static final String SIGNATURE_PACKAGING = "SIGNATURE_PACKAGING";

}
