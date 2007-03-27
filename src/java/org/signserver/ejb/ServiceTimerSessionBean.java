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

import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.SessionContext;
import javax.ejb.Timer;
import javax.ejb.TimerService;
import javax.transaction.HeuristicMixedException;
import javax.transaction.HeuristicRollbackException;
import javax.transaction.NotSupportedException;
import javax.transaction.RollbackException;
import javax.transaction.SystemException;
import javax.transaction.UserTransaction;

import org.ejbca.core.ejb.BaseSessionBean;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ServiceConfig;
import org.signserver.server.IWorker;
import org.signserver.server.ServiceExecutionFailedException;
import org.signserver.server.WorkerFactory;
import org.signserver.server.service.IService;


/**
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @ejb.bean description="Timed Object Session bean running the services"
 *   display-name="ServiceTimerSessionSB"
 *   name="ServiceTimerSession"
 *   jndi-name="ServiceTimerSession"
 *   local-jndi-name="ServiceTimerSessionLocal"
 *   view-type="both"
 *   type="Stateless"
 *   transaction-type="Bean"
 *
 * @weblogic.enable-call-by-reference True
 *
 * @ejb.env-entry name="DataSource"
 *   type="java.lang.String"
 *   value="${datasource.jndi-name-prefix}${datasource.jndi-name}"
 *   
 *
 * @ejb.env-entry
 *   description="Defines the JNDI name of the mail service used"
 *   name="MailJNDIName"
 *   type="java.lang.String"
 *   value="${mail.jndi-name}"
 *
 * @ejb.home extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.signserver.ejb.IServiceTimerSessionLocalHome"
 *   remote-class="org.signserver.ejb.IServiceTimerSessionHome"
 *
 * @ejb.interface extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.signserver.ejb.IServiceTimerSessionLocal"
 *   remote-class="org.signserver.ejb.IServiceTimerSessionRemote"
 *
 *
 * @ejb.ejb-external-ref description="The Global Config session bean"
 *   view-type="local"
 *   ref-name="ejb/GlobalConfigurationSessionLocal"
 *   type="Session"
 *   home="org.signserver.ejb.IGlobalConfigurationSessionLocalHome"
 *   business="org.signserver.ejb.IGlobalConfigurationSessionLocal"
 *   link="GlobalConfigurationSession"
 *   
 * @ejb.ejb-external-ref description="The Sign Session Bean"
 *   view-type="local"
 *   ref-name="ejb/SignServerSessionLocal"
 *   type="Session"
 *   home="org.signserver.ejb.ISignServerSessionSessionLocalHome"
 *   business="org.signserver.ejb.ISignServerSessionSessionLocal"
 *   link="SignServerSession"
 *
 * @ejb.ejb-external-ref
 *   description="The Worker Config Bean"
 *   view-type="local"
 *   ejb-name="WorkerConfigDataLocal"
 *   type="Entity"
 *   home="org.signserver.ejb.WorkerConfigDataLocalHome"
 *   business="org.signserver.ejb.WorkerConfigDataLocal"
 *   link="WorkerConfigData"
 *
 *  @jonas.bean ejb-name="ServiceTimerSession"
 */
public class ServiceTimerSessionBean extends BaseSessionBean implements javax.ejb.TimedObject {


	private static final long serialVersionUID = 1L;
  
    /**
     * Default create for SessionBean without any creation Arguments.
     *
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {    	    
    	workerConfigHome = (WorkerConfigDataLocalHome) getLocator().getLocalHome(WorkerConfigDataLocalHome.COMP_NAME);	
    }
    
    /**
     * Constant indicating the Id of the "service loader" service.
     * Used in a clustered environment to perodically load available
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
	public void ejbTimeout(Timer timer) {
		Integer timerInfo = (Integer) timer.getInfo();

		if(timerInfo.equals(SERVICELOADER_ID)){
			log.debug("Running the internal Service loader.");
			getSessionContext().getTimerService().createTimer(SERVICELOADER_PERIOD, SERVICELOADER_ID);
			load(0);
		}else{		
			ServiceConfig serviceConfig = null;
			IService service = null;
			boolean run = false;
			UserTransaction ut = getSessionContext().getUserTransaction();
			try{
				ut.begin();
				IWorker worker = WorkerFactory.getInstance().getWorker(timerInfo.intValue(), workerConfigHome, getGlobalConfigurationSession());
				if(worker != null){
					serviceConfig = new ServiceConfig( WorkerFactory.getInstance().getWorker(timerInfo.intValue(), workerConfigHome, getGlobalConfigurationSession()).getStatus().getActiveSignerConfig());
					if(serviceConfig != null){					
						service = (IService) WorkerFactory.getInstance().getWorker(timerInfo.intValue(), workerConfigHome, getGlobalConfigurationSession());
						getSessionContext().getTimerService().createTimer(service.getNextInterval()*1000, timerInfo);
						if(!service.isSingleton()){
							run=true;						
						}else{
							GlobalConfiguration gc = getGlobalConfigurationSession().getGlobalConfiguration();
							Date nextRunDate = new Date();
							if(gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL,"SERVICENEXTRUNDATE"+ timerInfo.intValue()) != null){
								nextRunDate = new Date(Long.parseLong(gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL,"SERVICENEXTRUNDATE"+ timerInfo.intValue())));
							}						
							Date currentDate = new Date();
							if(currentDate.after(nextRunDate)){
								nextRunDate = new Date(currentDate.getTime() + service.getNextInterval());							
								getGlobalConfigurationSession().setProperty(GlobalConfiguration.SCOPE_GLOBAL, "SERVICENEXTRUNDATE"+ timerInfo.intValue(), "" +nextRunDate.getTime());
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
						if(service.isActive() && service.getNextInterval() != IService.DONT_EXECUTE){				
							service.work();
							serviceConfig.setLastRunTimestamp(new Date());
							log.info("Service " + timerInfo.intValue() +  " executed successfully.");							
						}
					}catch (ServiceExecutionFailedException e) {
						log.error("Service" + timerInfo.intValue() + " execution failed. ",e);						
					}
				} else {
					log.error("Service with id " + timerInfo.intValue() + " not found.");																
				} 
			}else{
				log.info("Service " + timerInfo.intValue() +  " have been executed on another node in the cluster, waiting.");				
			}
		}
	}    

    /**
     * Loads and activates one or all the services from database that are active
     *
     * @param serviceId 0 indicates all services othervise is just the specified service loaded.
     * @throws EJBException             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
	public void load(int serviceId){
    	// Get all services
		    SessionContext context = getSessionContext();
		    TimerService timerService = context.getTimerService();
    		Collection currentTimers = timerService.getTimers();
    		Iterator iter = currentTimers.iterator();
    		HashSet existingTimers = new HashSet();
    		while(iter.hasNext()){
    			Timer timer = (Timer) iter.next();
    			existingTimers.add(timer.getInfo());    			
    		}

    		Collection serviceIds = null;
            if(serviceId == 0){    		
    		    serviceIds = getGlobalConfigurationSession().getWorkers(GlobalConfiguration.WORKERTYPE_SERVICES);
            }else{
            	serviceIds = new ArrayList();
            	serviceIds.add(new Integer(serviceId));
            }
			iter = serviceIds.iterator();
			while(iter.hasNext()){
				Integer nextId = (Integer) iter.next();								
				if(!existingTimers.contains(nextId)){					
					IService service = (IService) WorkerFactory.getInstance().getWorker(nextId.intValue(), workerConfigHome, globalConfigurationSession);
					if(service != null && service.isActive()  && service.getNextInterval() != IService.DONT_EXECUTE){
					  getSessionContext().getTimerService().createTimer((service.getNextInterval()) *1000, nextId);
					}
				}
			}
			
			if(!existingTimers.contains(SERVICELOADER_ID)){
				// load the service timer
				getSessionContext().getTimerService().createTimer(SERVICELOADER_PERIOD, SERVICELOADER_ID);
			}
			

	}
	
    /**
     * Cancels one or all existing timers 
     *
     * @param serviceId indicates all services othervise is just the specified service unloaded.
     * @throws EJBException             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
	public void unload(int serviceId){
		// Get all servicess
		Collection currentTimers = getSessionContext().getTimerService().getTimers();
		Iterator iter = currentTimers.iterator();
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
     *
     * @throws EJBException             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
	public void addTimer(long interval, Integer id){
		 getSessionContext().getTimerService().createTimer(interval, id);
	}
	
    /**
     * cancels a timer with the given Id
     *
     * @throws EJBException             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
	public void cancelTimer(Integer id){
		  Collection timers = getSessionContext().getTimerService().getTimers();
		  Iterator iter = timers.iterator();
		  while(iter.hasNext()){
			  Timer next = (Timer) iter.next();
			  if(id.equals(next.getInfo())){
				  next.cancel();
			  }
		  }
	}
	
	


	
    /** The local home interface of Worker Config entity bean. */
    private WorkerConfigDataLocalHome workerConfigHome = null;
	
    /**
     * Gets connection to global configuration session bean
     *
     * @return Connection
     */
    private IGlobalConfigurationSessionLocal getGlobalConfigurationSession() {
        if (globalConfigurationSession == null) {
            try {
                IGlobalConfigurationSessionLocalHome globalconfigurationsessionhome = (IGlobalConfigurationSessionLocalHome) getLocator().getLocalHome(IGlobalConfigurationSessionLocalHome.COMP_NAME);
                globalConfigurationSession = globalconfigurationsessionhome.create();
            } catch (CreateException e) {
                throw new EJBException(e);
            }
        }
        return globalConfigurationSession;
    } //getGlobalConfigurationSession
    
    private IGlobalConfigurationSessionLocal globalConfigurationSession = null;

    
	
	public void setSessionContext(SessionContext arg0) throws EJBException, RemoteException {		
		super.setSessionContext(arg0);
	}



} // LocalServiceSessionBean
