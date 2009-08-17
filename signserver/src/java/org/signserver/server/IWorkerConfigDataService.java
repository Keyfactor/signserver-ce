package org.signserver.server;

import org.signserver.common.WorkerConfig;

public interface IWorkerConfigDataService {

	WorkerConfig getWorkerProperties(int workerId);

}