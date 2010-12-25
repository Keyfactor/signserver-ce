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

package org.signserver.server.genericws.test;

import java.security.cert.X509Certificate;

import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebService;
import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.server.genericws.BaseWS;

/**
 * 
 * Dummy generic WS used for testing purposes.
 * 
 * @author Philip Vendil 8 okt 2008
 *
 * @version $Id$
 */

@WebService(targetNamespace="gen.genericws.server.signserver.org")
public class DummyWS extends BaseWS implements IDummyWS  {
	
	private static final Logger log = Logger.getLogger(DummyWS.class);
	
	/* (non-Javadoc)
	 * @see org.signserver.server.genericws.IDummyWS#test(java.lang.String)
	 */
	@WebMethod
	public String test(@WebParam(name="param1")String param1) throws IllegalRequestException, SignServerException{
	   log.info("WS test called param1 : " + param1);
	   
	   if(param1.equals("Test")){
		   return param1;   
	   }
	   
	   if(param1.equals("CertSN")){
			X509Certificate cert = (X509Certificate) getWorkerCertificate();
			return cert.getSubjectDN().toString();		   
	   }
	   
	   if(param1.equals("workerid")){
		   return "" + getWorkerId();
	   }
	   

	   if(param1.equals("dbtest")){
		   EntityManager em = getWorkerEntityManager();
		   em.getTransaction().begin();
		   BookDataBean b = em.find(BookDataBean.class, "test1");
		   if(b == null){
			   b = new BookDataBean();
			   b.setName("test1");
			   em.persist(b);
		   }else{
			   b.incrementCounter();
		   }
		   em.getTransaction().commit();
		   
		   em.getTransaction().begin();
		   ShelfDataBean s = em.find(ShelfDataBean.class, "test1");
		   if(s == null){
			   s = new ShelfDataBean();
			   s.setName("test1");
			   em.persist(s);
		   }else{
			   s.incrementCounter();
		   }
		   em.getTransaction().commit();
		   
		   return "success";
	   }
       
	   return null;
	}
}
