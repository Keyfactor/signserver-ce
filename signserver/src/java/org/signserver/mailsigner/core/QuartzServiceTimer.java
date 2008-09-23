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

package org.signserver.mailsigner.core;

import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.quartz.JobDetail;
import org.quartz.JobExecutionContext;
import org.quartz.Scheduler;
import org.quartz.SchedulerException;
import org.quartz.SimpleTrigger;
import org.quartz.Trigger;
import org.quartz.TriggerListener;
import org.quartz.impl.StdSchedulerFactory;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.ServiceConfig;
import org.signserver.mailsigner.MailSignerContext;
import org.signserver.server.IWorker;
import org.signserver.server.ServiceExecutionFailedException;
import org.signserver.server.WorkerFactory;
import org.signserver.server.timedservices.ITimedService;

/**
 * QuartzServiceTimer is a bean that works in the same way
 * as the TimedServiceSessionBean in the SignServer
 * but uses the quartz library for scheduling.
 * 
 * It have three public methods.
 * start() which loads all services and schedules them
 * stop() which stops all services
 * reload(int) which reloads a specific service.
 * 
 * @author Philip Vendil 18 sep 2008
 *
 * @version $Id$
 */

public class QuartzServiceTimer {

	private transient Logger log = Logger.getLogger(this.getClass());

	private static final String TIMEDSERVICESTRIGGERGROUP = "TimedServices";
	
	private static QuartzServiceTimer instance = null;
	
	public static QuartzServiceTimer getInstance(){
		if(instance == null){
			instance = new QuartzServiceTimer();
		}
		
		return instance;
	}
	
	private QuartzServiceTimer(){}
	
	/**
	 * Method used to start all configured services, is usually called
	 * upon start of server.
	 */
	public void start(){
	  log.debug(">Loading all timed services.");	
	  List<Integer> serviceIds = NonEJBGlobalConfigurationSession.getInstance().getWorkers(GlobalConfiguration.WORKERTYPE_SERVICES);
	  
	  try {
		  Scheduler scheduler = StdSchedulerFactory.getDefaultScheduler();

		  for(int serviceId : serviceIds){
			  ServiceTimerTriggerListener sttl = new ServiceTimerTriggerListener(serviceId);
			  scheduler.addTriggerListener(sttl);
			  sttl.addTrigger();
		  }
		  
		  scheduler.start();

	  } catch (SchedulerException e) {
		  log.error("Error occured during scheduling of timed service : " + e.getMessage(),e);
	  }
	  
	  log.debug("<Finished loading all timed services.");
	}

	/**
	 * Method used to stop all configured services, is usually called
	 * upon termination of server.
	 */
	public void stop(){
		log.debug(">Stopping all timed services.");	
		try{
			Scheduler scheduler = StdSchedulerFactory.getDefaultScheduler();
			scheduler.pauseAll();
            Set<?> tln = scheduler.getTriggerListenerNames();
            Iterator<?> iter = tln.iterator();
            while(iter.hasNext()){
            	String name = (String) iter.next();
            	scheduler.removeTriggerListener(name);
            }
            scheduler.shutdown();
		} catch (SchedulerException e) {
			log.error("Error occured when stopping timed services : " + e.getMessage(),e);
		}
		log.debug("<Finished stopping all timed services.");
	}
	
	/**
	 * Reloads the configuration of a specific service.
	 * 
	 * @param workerId of worker or 0 for all workers.
	 */
	public void reload(int workerId){
		log.debug(">Reloading service with worker Id " + workerId);	
		if(workerId == 0){
			stop();
			start();
		}else{
			try{
				List<Integer> serviceIds = NonEJBGlobalConfigurationSession.getInstance().getWorkers(GlobalConfiguration.WORKERTYPE_SERVICES);
				if(serviceIds.contains(workerId)){
					// Stop current trigger
					Scheduler scheduler = StdSchedulerFactory.getDefaultScheduler();

					String[] triggernames = scheduler.getTriggerNames(TIMEDSERVICESTRIGGERGROUP);
					for(String triggername : triggernames){
						if(triggername.equals("" + workerId)){
							scheduler.pauseTrigger(""+workerId, TIMEDSERVICESTRIGGERGROUP);
							scheduler.unscheduleJob(triggername, TIMEDSERVICESTRIGGERGROUP);
						}
					}

					Set<?> tln = scheduler.getTriggerListenerNames();
					Iterator<?> iter = tln.iterator();
					while(iter.hasNext()){					
						String tlname = (String) iter.next();
						if(tlname.equals(""+workerId)){
							scheduler.removeTriggerListener(tlname);
						}
					}

					// Add the new trigger listener
					ServiceTimerTriggerListener sttl = new ServiceTimerTriggerListener(workerId);
					scheduler.addTriggerListener(sttl);
					sttl.addTrigger();
				}
			} catch (SchedulerException e) {
				log.error("Error occured when reload timed services : " + e.getMessage(),e);
			}
		}
		
		log.debug("<Finished Reloading service with worker Id " + workerId);		
	}
	
	/**
	 * Method that finds and initializes a TimedService
	 */
	private ITimedService getTimedService(int workerId) throws InvalidWorkerIdException{
		
		IWorker worker = WorkerFactory.getInstance().getWorker(workerId, MailSignerWorkerConfigService.getInstance(), NonEJBGlobalConfigurationSession.getInstance(), new MailSignerContext(null));
		if(!(worker instanceof ITimedService)){
			log.error("Error: timed service with id '" + workerId + " doesn't implement the required ITimedService interface");
		}
		
		if(worker == null){
			throw new InvalidWorkerIdException("Error, couldn't find worker id " + workerId+ " in global configuration.");
		}
		return (ITimedService) worker;
	}
	
	private class ServiceTimerTriggerListener implements TriggerListener{

		private transient Logger log = Logger.getLogger(this.getClass());
		private int workerId = 0;
		private ITimedService timedService;
		
		private ServiceTimerTriggerListener(int workerId){
		  this.workerId = workerId;	
		  
		}
		
		public void addTrigger() {
			try{
				Scheduler scheduler = StdSchedulerFactory.getDefaultScheduler();
				if(timedService == null){
				  timedService = getTimedService(workerId);
				}
				long nextInterval = timedService.getNextInterval();
				if(timedService.isActive() && nextInterval != ITimedService.DONT_EXECUTE){				
						SimpleTrigger st = new SimpleTrigger("" + workerId, TIMEDSERVICESTRIGGERGROUP);
						st.addTriggerListener(""+workerId);
						st.setStartTime(new Date(System.currentTimeMillis() + nextInterval));
						st.setJobName("" + workerId);
						st.setJobGroup(TIMEDSERVICESTRIGGERGROUP);
						boolean jobExists = false;
						String[] currentJobs = scheduler.getJobNames(TIMEDSERVICESTRIGGERGROUP);
						for(String currentJob : currentJobs){
						  if(currentJob.equals(""+workerId)){
							  jobExists = true;;
							  break;
						  }
						}
						if(jobExists){
						  scheduler.rescheduleJob(""+ workerId, TIMEDSERVICESTRIGGERGROUP, st);	
						}else{
						  scheduler.scheduleJob(new JobDetail(""+ workerId, TIMEDSERVICESTRIGGERGROUP, DoNothingJob.class), st);
						}
				}
				
			} catch (SchedulerException e) {
				log.error("Error occured when adding trigger for timed services : " + e.getMessage(),e);
			} catch (InvalidWorkerIdException e) {
				log.error("Error occured when adding trigger for timed services : " + e.getMessage(),e);
			}
			
		}
		
		public String getName() {
			return "" + workerId;
		}

		public void triggerComplete(Trigger arg0, JobExecutionContext arg1,
				int arg2) {
              // Do Nothing			
		}

		public void triggerFired(Trigger arg0, JobExecutionContext arg1) {
			try {
				new ServiceConfig(timedService.getStatus().getActiveSignerConfig()).setLastRunTimestamp(new Date());
				timedService.work();
				addTrigger();
				log.info("Service " + workerId +  " executed successfully.");				
			} catch (ServiceExecutionFailedException e) {
				log.error("Service " + workerId +  " execution failed. " +e.getMessage(),e);
			}
			
		}

		public void triggerMisfired(Trigger arg0) {
			log.error("Error service execution for service with Id " + workerId + " failed.");		
		}

		public boolean vetoJobExecution(Trigger arg0, JobExecutionContext arg1) {
			return false;
		}
		
	}
	

	
}
