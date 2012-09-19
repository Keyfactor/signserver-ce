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

import java.util.List;
import java.util.Random;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.ejb.interfaces.IWorkerSession.IRemote;

/**
 * Holder for environment and configuration data.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class TestContext {
    
    private Random masterRandom;
    private IWorkerSession.IRemote workerSession;
    private FailureCallback callback;
    private Pauser pauser;
    private List<WorkerSpec> workerGroup1;
    private List<WorkerSpec> workerGroup2;
    private List<WorkerSpec> workerGroup3;
    private Integer threadsGroup1;
    private Integer threadsGroup2;

    public FailureCallback getCallback() {
        return callback;
    }

    public void setCallback(FailureCallback callback) {
        this.callback = callback;
    }

    public Random getMasterRandom() {
        return masterRandom;
    }

    public void setMasterRandom(Random masterRandom) {
        this.masterRandom = masterRandom;
    }

    public Pauser getPauser() {
        return pauser;
    }

    public void setPauser(Pauser pauser) {
        this.pauser = pauser;
    }

    public IRemote getWorkerSession() {
        return workerSession;
    }

    public void setWorkerSession(IRemote workerSession) {
        this.workerSession = workerSession;
    }

    public List<WorkerSpec> getWorkerGroup1() {
        return workerGroup1;
    }

    public void setWorkerGroup1(List<WorkerSpec> workerGroup1) {
        this.workerGroup1 = workerGroup1;
    }

    public List<WorkerSpec> getWorkerGroup2() {
        return workerGroup2;
    }
    
    public List<WorkerSpec> getWorkerGroup3() {
        return workerGroup3;
    }

    public void setWorkerGroup2(List<WorkerSpec> workerGroup2) {
        this.workerGroup2 = workerGroup2;
    }
    
    public void setWorkerGroup3(List<WorkerSpec> workerGroup3) {
        this.workerGroup3 = workerGroup3;
    }

    public Integer getThreadsGroup1() {
        return threadsGroup1;
    }

    public void setThreadsGroup1(Integer threadsGroup1) {
        this.threadsGroup1 = threadsGroup1;
    }

    public Integer getThreadsGroup2() {
        return threadsGroup2;
    }

    public void setThreadsGroup2(Integer threadsGroup2) {
        this.threadsGroup2 = threadsGroup2;
    }
    
}
