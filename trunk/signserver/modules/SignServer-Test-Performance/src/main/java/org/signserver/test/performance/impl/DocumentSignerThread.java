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
 * @version $Id: PDFSignerThread.java 3423 2013-04-08 11:18:17Z malu9369 $
 *
 */
public class DocumentSignerThread extends WorkerThread {
    
    
    public DocumentSignerThread(final String name, final FailureCallback failureCallback, final String url, 
            final boolean useWorkerServlet, final byte[] data, final File infile, final String workerNameOrId, final String processType,
            int maxWaitTime,
            int seed, long warmupTime, final long limitedTime, final File statFile,
            final String userPrefix, final Integer userSuffixMin, final Integer userSuffixMax,
            final boolean continueOnFailure) {
        super(name, failureCallback, maxWaitTime, seed, warmupTime, limitedTime,
              statFile, continueOnFailure);
        this.task = new DocumentSigner(url, useWorkerServlet, data, infile, workerNameOrId, processType, random, userPrefix, userSuffixMin, userSuffixMax);
    }
}
