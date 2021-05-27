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
package org.signserver.common.worker;

/**
 * Class containing the collection of configuration properties for a worker.
 *
 * @author Andrey Sergeev
 * @version $Id$
 */
public class WorkerConfigProperty {

    //==================================================================================================================
    // AdES
    //==================================================================================================================
    /**
     * AdES signature format property. Reflects values: PAdES, XAdES.
     */
    public static final String AdES_SIGNATURE_FORMAT = "SIGNATURE_FORMAT";

    /**
     * AdES packaging property. Reflects values: Enveloped, Enveloping, Detached, Internally detached.
     */
    public static final String AdES_PACKAGING = "PACKAGING";
}
