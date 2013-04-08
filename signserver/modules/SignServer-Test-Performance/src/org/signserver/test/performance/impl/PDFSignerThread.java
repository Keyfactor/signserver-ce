package org.signserver.test.performance.impl;

import java.io.File;

import org.signserver.test.performance.FailureCallback;
import org.signserver.test.performance.WorkerThread;

public class PDFSignerThread extends WorkerThread {
    
    
    public PDFSignerThread(final String name, final FailureCallback failureCallback, final String url, final File infile, final String workerNameOrId,
            int maxWaitTime,
            int seed, long warmupTime, final long limitedTime, final File statFile) {
        super(name, failureCallback, limitedTime, seed, warmupTime, limitedTime, statFile);
        this.task = new PDFSign(url, infile, workerNameOrId, random);
    }
}
