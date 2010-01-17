package org.signserver.server;

import org.signserver.common.WorkerConfig;

public interface IWorkerConfigDataService {

    String LOG_OPERATION = "WORKERCONF_OPERATION";

	WorkerConfig getWorkerProperties(int workerId);

}