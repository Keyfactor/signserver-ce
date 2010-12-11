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
 
package org.signserver.module.wsra.core;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;

import org.apache.log4j.Logger;
import org.signserver.module.wsra.beans.TransactionDataBean;
import org.signserver.module.wsra.common.WSRAConstants;

/**
 * Class in charge of logic concerning transaction
 * of products with an organization
 * 
 * All manipulation of Transaction Data should go
 * through this class.
 * 
 * 
 * @author Philip Vendil 11 okt 2008
 *
 * @version $Id$
 */

public class TransactionManager {
	
	private Logger log = Logger.getLogger(this.getClass());

	private EntityManager workerEntityManager;

	private int nodeIdHash;
	
	
	public TransactionManager(EntityManager workerEntityManager, String nodeId){		
		this.workerEntityManager = workerEntityManager;
		if(nodeId == null){
			this.nodeIdHash = 0;
		}else{
			this.nodeIdHash = nodeId.hashCode();	
		}
		
	}
	
	/**
	 * Method that adds a new transaction to the system.
	 * 
	 * The status of the transaction is always set to
	 * TRANSACTIONSTATUS_UNPROCESSED.
	 * 
	 * @param transaction containing information about the
	 * new transaction.
	 * @return the new transactionId
	 */
    public int addTransaction(TransactionDataBean transaction){
    	transaction.setStatus(WSRAConstants.TRANSACTIONSTATUS_UNPROCESSED);    	
    	workerEntityManager.persist(transaction);
    	return transaction.getId();
    }
	
	/**
	 * Method that lists all transactions with a given status within
	 * a specified time frame.
	 * 
	 * @param startDate of transaction
	 * @param endDate of transaction
	 * @param status one of TransactionDataBean.STATUS_ constants or 0 for all statuses.
	 * @return a list of transactions that fulfill the requirements, never null
	 */
	@SuppressWarnings("unchecked")
	public List<TransactionDataBean> listTransactions(Date startDate, Date endDate, int status){
		List<TransactionDataBean> retval = new ArrayList<TransactionDataBean>();
		
		try{
			if(status == 0){
				retval = workerEntityManager.createNamedQuery("TransactionDataBean.findTransactionByTime")
		                                   .setParameter(1, startDate.getTime())
		                                   .setParameter(2, endDate.getTime())
		                                   .getResultList();
				
			}else{
				retval = workerEntityManager.createNamedQuery("TransactionDataBean.findTransactionByTimeAndStatus")
                                          .setParameter(1, startDate.getTime())
                                          .setParameter(2, endDate.getTime())
                                          .setParameter(3, status)
                                          .getResultList(); 
				
			}
		}catch(NoResultException e){}
		
		return retval;
	}
	
	/**
	 * Method that gets all unprocessed data, and marks them
	 * with IN_PROCESS with the current nodeId.
	 * 
	 * This method is the one that should be used when fetching
	 * data to be invoiced to organizations.
	 * 
	 * After the invoices have been done should a markAsProcessed call be done.
	 * 
	 * @param startDate of transaction
	 * @param endDate of transaction
	 * @return a list of transactions that fulfill the requirements, never null
	 */
	@SuppressWarnings("unchecked")
	public List<TransactionDataBean> getUnprocessed(Date startDate, Date endDate){
		List<TransactionDataBean> retval = new ArrayList<TransactionDataBean>();
		
		try{
		
				int size = workerEntityManager.createNamedQuery("TransactionDataBean.updateByStatus")
				                           .setParameter(1, nodeIdHash)
				                           .setParameter(2, WSRAConstants.TRANSACTIONSTATUS_PROCESSING)
		                                   .setParameter(3, startDate.getTime())
		                                   .setParameter(4, endDate.getTime())
		                                   .setParameter(5, WSRAConstants.TRANSACTIONSTATUS_UNPROCESSED)
		                                   .executeUpdate();
		        workerEntityManager.getTransaction().commit();
		        workerEntityManager.getTransaction().begin();
				retval = workerEntityManager.createNamedQuery("TransactionDataBean.findByNodeAndStatus")
                                           .setParameter(1, nodeIdHash)
                                           .setParameter(2, startDate.getTime())
                                           .setParameter(3, endDate.getTime())
                                           .setParameter(4, WSRAConstants.TRANSACTIONSTATUS_PROCESSING)
                                           .getResultList();				
				if(size != retval.size()){
					log.error("Error size of update didn't match select when fetching unprocessed transactions.");
				}		
		}catch(NoResultException e){}
		
		return retval;
	}
	
	/**
	 * Method that sets all transactions to processed that
	 * have status PROCESSING and belongs to this nodeId
	 * 
	 * This method is the one that should be used when finishing
	 * the invoices.
	 * 
	 * @param startDate of transaction
	 * @param endDate of transaction
	 * 
	 */
	@SuppressWarnings("unchecked")
	public void markAsProcessed(Date startDate, Date endDate){

		try{
			workerEntityManager.createNamedQuery("TransactionDataBean.updateByStatusAndNode")
				                           .setParameter(1, 0)
				                           .setParameter(2, WSRAConstants.TRANSACTIONSTATUS_PROCESSED)
				                           .setParameter(3, nodeIdHash)
		                                   .setParameter(4, startDate.getTime())
		                                   .setParameter(5, endDate.getTime())
		                                   .setParameter(6, WSRAConstants.TRANSACTIONSTATUS_PROCESSING)
		                                   .executeUpdate();
		}catch(NoResultException e){}
		
	}
	
	
	/**
	 * Method that removes a set of transactions during
	 * a timespan.
	 * 
	 * This method should generally only be called from
	 * test scripts.
	 * 
	 * @param userId the unique id of user.
	 */
	public void removeTransactions(Date startDate, Date endDate){
		try{			
			workerEntityManager.createNamedQuery("TransactionDataBean.deleteByTime")
		                                   .setParameter(1, startDate.getTime())
		                                   .setParameter(2, endDate.getTime())		                                   
		                                   .executeUpdate();			
		}catch(NoResultException e){}
	}


}
