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

package org.signserver.ejb;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.Timeout;
import javax.ejb.Timer;
import javax.ejb.TimerService;
import javax.ejb.TransactionManagement;
import javax.ejb.TransactionManagementType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.HeuristicMixedException;
import javax.transaction.HeuristicRollbackException;
import javax.transaction.NotSupportedException;
import javax.transaction.RollbackException;
import javax.transaction.SystemException;
import javax.transaction.UserTransaction;

import org.apache.log4j.Logger;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ServiceConfig;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IServiceTimerSession;
import org.signserver.server.IWorker;
import org.signserver.server.IWorkerConfigDataService;
import org.signserver.server.ServiceExecutionFailedException;
import org.signserver.server.SignServerContext;
import org.signserver.server.WorkerFactory;
import org.signserver.server.timedservices.ITimedService;


/**
 * Timed service session bean running services on a timely basis.
 */
@Stateless
@TransactionManagement(TransactionManagementType.BEAN)
public class ServiceTimerSessionBean implements IServiceTimerSession.ILocal, IServiceTimerSession.IRemote  {

    @PersistenceContext(unitName="SignServerJPA")
    EntityManager em;

	@Resource
	private SessionContext sessionCtx;
	
	@EJB
	private IGlobalConfigurationSession.ILocal globalConfigurationSession;
	
	private IWorkerConfigDataService workerConfigService = null;
	
	
	
	private static final long serialVersionUID = 1L;
  
	/** Log4j instance for actual implementation class */
	private static final Logger log = Logger.getLogger(ServiceTimerSessionBean.class);
	
    /**
     * Default create for SessionBean without any creation Arguments.
     */
	@PostConstruct
    public void create(){    	    
    	workerConfigService = new WorkerConfigDataService(em);
    }		
    
    /**
     * Constant indicating the Id of the "service loader" service.
     * Used in a clustered environment to periodically load available
     * services
     */
    private static final Integer SERVICELOADER_ID = new Integer(0);
    
    private static final long SERVICELOADER_PERIOD = 5 * 60 * 1000;

    /**
     * Method implemented from the TimerObject and is the main method of this
     * session bean. It calls the work object for each object.
     * 
     * @param timer
     */
    @Timeout
	public void ejbTimeout(Timer timer) {
		Integer timerInfo = (Integer) timer.getInfo();

		if(timerInfo.equals(SERVICELOADER_ID)){
			log.debug("Running the internal Service loader.");
			sessionCtx.getTimerService().createTimer(SERVICELOADER_PERIOD, SERVICELOADER_ID);
			load(0);
		}else{		
			ServiceConfig serviceConfig = null;
			ITimedService timedService = null;
			boolean run = false;
			boolean isSingleton = false;
			UserTransaction ut = sessionCtx.getUserTransaction();
			try{
				ut.begin();
				IWorker worker = WorkerFactory.getInstance().getWorker(timerInfo.intValue(), workerConfigService, globalConfigurationSession, new SignServerContext(em));
				if(worker != null){
					serviceConfig = new ServiceConfig( WorkerFactory.getInstance().getWorker(timerInfo.intValue(), workerConfigService, globalConfigurationSession,new SignServerContext(em)).getStatus().getActiveSignerConfig());
					if(serviceConfig != null){					
						timedService = (ITimedService) WorkerFactory.getInstance().getWorker(timerInfo.intValue(), workerConfigService, globalConfigurationSession,new SignServerContext(em));
						sessionCtx.getTimerService().createTimer(timedService.getNextInterval(), timerInfo);
						isSingleton = timedService.isSingleton();
						if(!isSingleton){
							run=true;						
						}else{
							GlobalConfiguration gc = globalConfigurationSession.getGlobalConfiguration();
							Date nextRunDate = new Date(0);
							if(gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL,"SERVICENEXTRUNDATE"+ timerInfo.intValue()) != null){
								nextRunDate = new Date(Long.parseLong(gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL,"SERVICENEXTRUNDATE"+ timerInfo.intValue())));
							}						
							Date currentDate = new Date();
							if(currentDate.after(nextRunDate)){
								nextRunDate = new Date(currentDate.getTime() + timedService.getNextInterval());							
								globalConfigurationSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "SERVICENEXTRUNDATE"+ timerInfo.intValue(), "" +nextRunDate.getTime());
								run=true;
							}
						}
					}
				}
			}catch(NotSupportedException e){
				log.error(e);
			} catch (SystemException e) {
				log.error(e);
			} catch (SecurityException e) {
				log.error(e);
			} catch (IllegalStateException e) {
				log.error(e);
			} finally {
				try {
					ut.commit();					
				} catch (RollbackException e) {
					log.error(e);
				} catch (HeuristicMixedException e) {
					log.error(e);
				} catch (HeuristicRollbackException e) {
					log.error(e);
				} catch (SystemException e) {
					log.error(e);
				}
			}

			if(run){
				if(serviceConfig != null){					
					try{
						if(timedService.isActive() && timedService.getNextInterval() != ITimedService.DONT_EXECUTE){				
							timedService.work();
							serviceConfig.setLastRunTimestamp(new Date());
							log.info("Service " + timerInfo.intValue() +  " executed successfully.");							
						}
					}catch (ServiceExecutionFailedException e) {
						log.error("Service" + timerInfo.intValue() + " execution failed. ",e);						
					} catch (RuntimeException e) {
						/*
						 * DSS-377:
						 * If the service worker fails with a RuntimeException we need to
						 * swallow this here. If we allow it to propagate outside the
						 * ejbTimeout method it is up to the application server config how it
						 * should be retried, but we have already scheduled a new try
						 * previously in this method. We still want to log this as an ERROR
						 * since it is some kind of catastrophic failure..
						 */
						log.error("Service worker execution failed.", e);
					}
				} else {
					log.error("Service with id " + timerInfo.intValue() + " not found.");																
				} 
			}else{
				if(isSingleton){
				  log.info("Service " + timerInfo.intValue() +  " have been executed on another node in the cluster, waiting.");
				}
			}
		}
	}    

    /**
     * Loads and activates one or all the services from database that are active
     *
     * @param serviceId 0 indicates all services otherwise is just the specified service loaded.
     */
	public void load(int serviceId){
    	// Get all services
		    TimerService timerService = sessionCtx.getTimerService();
    		Collection<?> currentTimers = timerService.getTimers();
    		Iterator<?> iter = currentTimers.iterator();
    		HashSet<Serializable> existingTimers = new HashSet<Serializable>();
    		while(iter.hasNext()){
    			Timer timer = (Timer) iter.next();
    			existingTimers.add(timer.getInfo());    			
    		}

    		Collection<Integer> serviceIds = null;
            if(serviceId == 0){    		
    		    serviceIds = globalConfigurationSession.getWorkers(GlobalConfiguration.WORKERTYPE_SERVICES);
            }else{
            	serviceIds = new ArrayList<Integer>();
            	serviceIds.add(new Integer(serviceId));
            }
			iter = serviceIds.iterator();
			while(iter.hasNext()){
				Integer nextId = (Integer) iter.next();								
				if(!existingTimers.contains(nextId)){					
					ITimedService timedService = (ITimedService) WorkerFactory.getInstance().getWorker(nextId.intValue(), workerConfigService, globalConfigurationSession, new SignServerContext(em));
					if(timedService != null && timedService.isActive()  && timedService.getNextInterval() != ITimedService.DONT_EXECUTE){
					  sessionCtx.getTimerService().createTimer((timedService.getNextInterval()), nextId);
					}
				}
			}
			
			if(!existingTimers.contains(SERVICELOADER_ID)){
				// load the service timer
				sessionCtx.getTimerService().createTimer(SERVICELOADER_PERIOD, SERVICELOADER_ID);
			}
			

	}
	
    /**
     * Cancels one or all existing timers 
     *
     * @param serviceId indicates all services otherwise is just the specified service unloaded.
     */
	public void unload(int serviceId){
		// Get all services
		Collection<?> currentTimers = sessionCtx.getTimerService().getTimers();
		Iterator<?> iter = currentTimers.iterator();
		while(iter.hasNext()){
			Timer timer = (Timer) iter.next();	
			if(serviceId == 0){
			   timer.cancel();
			}else{
				if(timer.getInfo() instanceof Integer){
					if(((Integer) timer.getInfo()).intValue() == serviceId){
						timer.cancel();
					}
				}
			}
		}
	}
	
	
    /**
     * Adds a timer to the bean
     */
	public void addTimer(long interval, Integer id){
		 sessionCtx.getTimerService().createTimer(interval, id);
	}
	
    /**
     * cancels a timer with the given Id
     *
     */
	public void cancelTimer(Integer id){
		  Collection<?> timers = sessionCtx.getTimerService().getTimers();
		  Iterator<?> iter = timers.iterator();
		  while(iter.hasNext()){
			  Timer next = (Timer) iter.next();
			  if(id.equals(next.getInfo())){
				  next.cancel();
			  }
		  }
	}

} 
