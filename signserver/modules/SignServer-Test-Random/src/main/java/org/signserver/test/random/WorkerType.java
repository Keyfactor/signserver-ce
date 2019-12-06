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
package org.signserver.test.random;

/**
 * All supported types of workers.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public enum WorkerType {
    /** XMLSigner. */
    xml, 
    
    /** TimeStampSigner. */
    tsa,
    
    /** RenewalWorker. */
    renew
}
