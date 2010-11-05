package org.signserver.module.wsra.core;

import java.util.HashSet;
import java.util.Properties;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContextType;
import javax.persistence.spi.PersistenceUnitTransactionType;

import junit.framework.TestCase;

import org.hibernate.SessionFactory;
import org.hibernate.cfg.AnnotationConfiguration;
import org.signserver.module.wsra.beans.AuthDataBean;
import org.signserver.module.wsra.beans.CertificateDataBean;
import org.signserver.module.wsra.beans.DataBankDataBean;
import org.signserver.module.wsra.beans.OrganizationDataBean;
import org.signserver.module.wsra.beans.PricingDataBean;
import org.signserver.module.wsra.beans.ProductDataBean;
import org.signserver.module.wsra.beans.ProductsInOrganizationDataBean;
import org.signserver.module.wsra.beans.TokenDataBean;
import org.signserver.module.wsra.beans.TransactionDataBean;
import org.signserver.module.wsra.beans.UserAliasDataBean;
import org.signserver.module.wsra.beans.UserDataBean;
import org.signserver.module.wsra.common.tokenprofiles.JKSTokenProfile;

public class CommonManagerTest extends TestCase {

	protected static EntityManager workerEntityManager = null;
	
	protected void setUp() throws Exception {
		super.setUp();
		if(workerEntityManager == null){
			workerEntityManager = genEntityManager();
		}		
	}
	    
	protected EntityManager genEntityManager(){
		AnnotationConfiguration ac = new AnnotationConfiguration();
		Properties props = new Properties();
		props.setProperty("hibernate.dialect", "org.hibernate.dialect.HSQLDialect");
		props.setProperty("hibernate.connection.driver_class","org.hsqldb.jdbcDriver");
		props.setProperty("hibernate.connection.url","jdbc:hsqldb:mem:wsra");
		props.setProperty("hibernate.connection.pool_size","1");
		props.setProperty("hibernate.connection.username","sa");
		props.setProperty("hibernate.connection.password","");

		props.setProperty("hibernate.hbm2ddl.auto","create");
		
		ac.addAnnotatedClass(UserDataBean.class);
		ac.addAnnotatedClass(UserAliasDataBean.class);
		ac.addAnnotatedClass(OrganizationDataBean.class);
		ac.addAnnotatedClass(DataBankDataBean.class);
		ac.addAnnotatedClass(TokenDataBean.class);
		ac.addAnnotatedClass(AuthDataBean.class);
		ac.addAnnotatedClass(CertificateDataBean.class);
		ac.addAnnotatedClass(PricingDataBean.class);
		ac.addAnnotatedClass(ProductDataBean.class);
		ac.addAnnotatedClass(ProductsInOrganizationDataBean.class);
		ac.addAnnotatedClass(TransactionDataBean.class);
		ac.setProperties(props);
		SessionFactory sf = ac.buildSessionFactory();
		
		return EntityManagerUtil.createEntityManager(sf,PersistenceContextType.TRANSACTION,PersistenceUnitTransactionType.RESOURCE_LOCAL,true,new Properties());
	}
	
	protected HashSet<Class<?>> getAvailableTokenProfiles(){
		HashSet<Class<?>> retval = new HashSet<Class<?>>();
		retval.add(JKSTokenProfile.class);
		return retval;
	}
	
	/**
	 * Begin Transaction
	 */
	protected void tb(){
		workerEntityManager.getTransaction().begin();
	}
	
	/**
	 * Rollback Transaction
	 */
	protected void tr(){
		workerEntityManager.getTransaction().rollback();
	}
	
	/**
	 * Commit Transaction
	 */
	protected void tc(){
		workerEntityManager.getTransaction().commit();
	}
}
