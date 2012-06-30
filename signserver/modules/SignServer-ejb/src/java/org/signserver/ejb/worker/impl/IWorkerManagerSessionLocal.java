/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.ejb.worker.impl;

import java.util.List;
import javax.ejb.Local;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.WorkerSessionBean;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession.ILocal;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.IAccounter;
import org.signserver.server.IAuthorizer;
import org.signserver.server.IWorker;
import org.signserver.server.archive.Archiver;
import org.signserver.server.log.IWorkerLogger;

/**
 *
 * @author markus
 */
@Local
public interface IWorkerManagerSessionLocal {

    IWorker getWorker(final int workerId, final IGlobalConfigurationSession globalSession);

    int getIdFromName(final String workerName, final IGlobalConfigurationSession globalSession);

    void reloadWorker(int workerId, WorkerSessionBean aThis, ILocal globalConfigurationSession);

    IWorkerLogger getWorkerLogger(int workerId, WorkerConfig awc) throws IllegalRequestException;

    IAuthorizer getAuthenticator(int workerId, String authenticationType, WorkerConfig awc) throws IllegalRequestException;

    IAccounter getAccounter(int workerId, WorkerConfig awc) throws IllegalRequestException;

    List<Archiver> getArchivers(int workerId, WorkerConfig awc) throws IllegalRequestException;

    void flush();

    List<Integer> getWorkers(int workerType, IGlobalConfigurationSession globalConfigurationSession);
    
}
