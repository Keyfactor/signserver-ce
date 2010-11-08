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
 
package org.signserver.server.clusterclassloader;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Properties;

import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContextType;
import javax.persistence.spi.PersistenceUnitTransactionType;

import org.apache.log4j.Logger;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.AnnotationConfiguration;
import org.signserver.common.SignServerConstants;
import org.signserver.common.WorkerConfig;
import org.signserver.common.clusterclassloader.ClusterClassLoaderUtils;

/**
 * An extended ClusterClassLoader with support for JPA.
 * 
 * It contains a method getWorkerEntityManager that initializes
 * a worker specific entity manager with all the entity beans
 * in the module.
 * 
 * 
 * @author Philip Vendil 6 okt 2008
 *
 * @version $Id$
 */

public class ExtendedClusterClassLoader extends ClusterClassLoader implements
        IEntityManagerSupport {
	
	private Logger log = Logger.getLogger(this.getClass());

	public ExtendedClusterClassLoader(ClassLoader parent, EntityManager em,
			String moduleName, String part, int version) {
		super(parent, em, moduleName, part, version);
	}

	public ExtendedClusterClassLoader(ClassLoader parent, EntityManager em,
			String moduleName, String part) {
		super(parent, em, moduleName, part);
	}

	/**
	 * It contains a method getWorkerEntityManager that initializes
     * a worker specific entity manager with all the entity beans
     * in the module.
	 * @param workerConfig the current worker configuration
	 * @return a worker specific Entity Manager with all the Entity Beans
	 * in the module part.
	 */
	public EntityManager getWorkerEntityManger(WorkerConfig workerConfig){
		if(workerEm == null){
			if(workerConfig.getProperty(SignServerConstants.USEWORKERENTITYMANAGER,"FALSE").equalsIgnoreCase("TRUE")){
				ArrayList<Class<?>> entityBeans = new ArrayList<Class<?>>();
				Collection<Class<?>> classes = loadedClasses.values();
				for(Class<?> c : classes){

					if(c.getAnnotation(Entity.class) != null){
						entityBeans.add(c);
						log.debug("Found Entity Bean : " + c.getName());
					}
				}

				Properties currentConfig = workerConfig.getProperties();
				Properties emConfig = new Properties();
				Enumeration<?> e = currentConfig.propertyNames();
				while(e.hasMoreElements()){
					String property = (String) e.nextElement();
					if(property.startsWith("HIBERNATE")){
						emConfig.setProperty(property.toLowerCase(), currentConfig.getProperty(property));
					}
				}

				AnnotationConfiguration ac = new AnnotationConfiguration();
				ac.setProperties(emConfig);
				for(Class<?> c : entityBeans){
					ac.addAnnotatedClass(c);
				}

				ClassLoader orgContextClassLoader = Thread.currentThread().getContextClassLoader();
				try{
				  Thread.currentThread().setContextClassLoader(this);
				  SessionFactory sf = ac.buildSessionFactory();
				  workerEm = EntityManagerUtil
                                          .createEntityManager(sf,
                                          PersistenceContextType.TRANSACTION,
                                          PersistenceUnitTransactionType
                                            .RESOURCE_LOCAL, true, emConfig);
				}finally{
					Thread.currentThread().setContextClassLoader(orgContextClassLoader);
				}
			}
		}

		return workerEm;
	}
	private EntityManager workerEm = null;

	/**
	 * Overridden method that injects transaction data
	 * on all classes with org.signserver.server.annotations.Transaction
	 * annotation.
	 * 
	 * @param classData original class data.
	 * @return injected classData
	 */
	protected byte[] performInjections(byte[] classData) {		
		return ClusterClassLoaderUtils.injectTransaction(classData);
	}

    
		
}
