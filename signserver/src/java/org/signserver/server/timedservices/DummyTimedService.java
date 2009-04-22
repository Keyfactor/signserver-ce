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
 
package org.signserver.server.timedservices;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.signserver.common.WorkerConfig;
import org.signserver.server.ServiceExecutionFailedException;
import org.signserver.server.WorkerContext;

/**
 * Dummy Service that is used for testing and demonstration purposes.
 * Only output to the log that it have been called
 * 
 * 
 * @author Philip Vendil 2007 jan 23
 *
 * @version $Id$
 */

public class DummyTimedService extends BaseTimedService {

	public transient Logger log = Logger.getLogger(this.getClass());
	
    String outPath = null;
	
	@Override
	public void init(int workerId, WorkerConfig config, WorkerContext workerContext,EntityManager workerEntityManager) {
		super.init(workerId, config, workerContext, workerEntityManager);
		
		outPath = config.getProperties().getProperty("OUTPATH");
		
		log.info("Initializing DummyTimedService, output path : " + outPath);
	}
	
	/**
	 * Example of super simple service.
	 * 
	 * @see org.signserver.server.timedservices.ITimedService#work()
	 */
	public void work() throws ServiceExecutionFailedException {
		
		int currentCount = 0;
		
		try{
		  FileInputStream fis = new FileInputStream(outPath);
		  ByteArrayOutputStream baos = new ByteArrayOutputStream();
		  int next = 0;
		  while((next = fis.read()) != -1){
			  baos.write(next);
		  }
		  fis.close();
		  currentCount = Integer.parseInt(new String(baos.toByteArray()));
		}catch(FileNotFoundException e){
		}catch(IOException e){
			throw new ServiceExecutionFailedException(e.getClass().getName() + " : " + e.getMessage());
		}
		currentCount++;
		try{
			FileOutputStream fos = new FileOutputStream(outPath);
			fos.write(("" + currentCount).getBytes());
			fos.close();
		}catch(IOException e){
			throw new ServiceExecutionFailedException(e.getClass().getName() + " : " + e.getMessage());
		}
		
		log.info("DummyTimedService.work() called. current count : " + currentCount);
	}

}
