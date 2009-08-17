package org.signserver.common.clusterclassloader;

import javax.persistence.EntityManager;

import org.signserver.server.annotations.WorkerEntityManager;

public class BaseClass {
	@WorkerEntityManager
	protected EntityManager workerEntityManager = new TEntityManager(); 

	public void setWorkerEntityManager(EntityManager em){
		workerEntityManager = em;
	}
}
