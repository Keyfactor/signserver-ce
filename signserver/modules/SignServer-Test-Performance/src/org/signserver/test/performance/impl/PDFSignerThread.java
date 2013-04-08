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
package org.signserver.test.performance.impl;

import java.io.File;

import org.signserver.test.performance.FailureCallback;
import org.signserver.test.performance.WorkerThread;

/**
 * Thread invoking a document signer.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class PDFSignerThread extends WorkerThread {
    
    
    public PDFSignerThread(final String name, final FailureCallback failureCallback, final String url, final File infile, final String workerNameOrId,
            int maxWaitTime,
            int seed, long warmupTime, final long limitedTime, final File statFile) {
        super(name, failureCallback, limitedTime, seed, warmupTime, limitedTime, statFile);
        this.task = new PDFSign(url, infile, workerNameOrId, random);
    }
}
