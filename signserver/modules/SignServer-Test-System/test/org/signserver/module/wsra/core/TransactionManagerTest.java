package org.signserver.module.wsra.core;

import java.util.Date;
import java.util.List;

import org.signserver.module.wsra.beans.TransactionDataBean;
import org.signserver.module.wsra.common.WSRAConstants;

public class TransactionManagerTest extends CommonManagerT {
	
	private static TransactionManager tm1 = null;
	private static TransactionManager tm2 = null;

	private static final int ORG1 = 1;
	private static final int ORG2 = 2;
	private static final int ORG3 = 3;
	
	private static final int PROD1 = 11;
	private static final int PROD2 = 12;
	private static final int PROD3 = 13;
	
	protected void setUp() throws Exception {
		super.setUp();
		if(tm1 == null){		  
		  tm1 = new TransactionManager(workerEntityManager,"node1");
		  tm2 = new TransactionManager(workerEntityManager,"node2");						
		}
	}
	
	public void test01BasicUserManager() throws Exception{
		TransactionDataBean t1 = new TransactionDataBean(ORG1,PROD1,1,new Date(),new Date());
		TransactionDataBean t2 = new TransactionDataBean(ORG2,PROD1,10,new Date(),new Date(System.currentTimeMillis() + 10000));
		TransactionDataBean t3 = new TransactionDataBean(ORG3,PROD3,12,new Date(),new Date());
		TransactionDataBean t4 = new TransactionDataBean(ORG1,PROD2,10,new Date(),new Date());
		tb();int id = tm1.addTransaction(t1);tc();
		assertTrue(id !=0);
		tb();int id2 = tm1.addTransaction(t2);tc();
		assertTrue(id2 !=0 && id != id2);
		tb();tm1.addTransaction(t3);tc();
		tb();tm1.addTransaction(t4);tc();
		
		Date startDate = new Date(System.currentTimeMillis() -1000);
		Date endDate = new Date(System.currentTimeMillis() +10000);		

		List<TransactionDataBean> result = tm1.listTransactions(startDate, endDate, 0);
		assertTrue(result.size() == 4);
		result = tm1.listTransactions(startDate, endDate, WSRAConstants.TRANSACTIONSTATUS_UNPROCESSED);
		assertTrue(result.size() == 4);
		int maxOrgId = Integer.MIN_VALUE;
		for(TransactionDataBean r : result){
			assertTrue(r.getOrganizationId() >= maxOrgId);
			maxOrgId = r.getOrganizationId();
		}
		result = tm1.listTransactions(startDate, endDate, WSRAConstants.TRANSACTIONSTATUS_PROCESSED);
		assertTrue(result.size() == 0);
		
		tb();result = tm1.getUnprocessed(startDate, endDate);tc();
		assertTrue(result.size() == 4);
		maxOrgId = Integer.MIN_VALUE;
		for(TransactionDataBean r : result){
			assertTrue(r.getOrganizationId() >= maxOrgId);
			assertTrue(r.getStatus() == WSRAConstants.TRANSACTIONSTATUS_PROCESSING);
			assertTrue(r.getNodeId() == "node1".hashCode());
			maxOrgId = r.getOrganizationId();
		}
		
		tb();tm1.markAsProcessed(startDate, endDate);tc();
		result = tm1.listTransactions(startDate, endDate, WSRAConstants.TRANSACTIONSTATUS_PROCESSED);
		assertTrue(result.size() == 4);
		for(TransactionDataBean r : result){
			assertTrue(r.getStatus() == WSRAConstants.TRANSACTIONSTATUS_PROCESSED);
			assertTrue(r.getNodeId() == 0);
		}
		
		TransactionDataBean t5 = new TransactionDataBean(ORG1,PROD1,1,new Date(),new Date());
		TransactionDataBean t6 = new TransactionDataBean(ORG2,PROD1,10,new Date(),new Date(System.currentTimeMillis() + 10000));
		tb();tm1.addTransaction(t5);tc();
		tb();tm1.addTransaction(t6);tc();
		tb();result = tm1.getUnprocessed(startDate, endDate);tc();
		assertTrue(result.size() == 2);
		TransactionDataBean t7 = new TransactionDataBean(ORG1,PROD1,1,new Date(),new Date());
		TransactionDataBean t8 = new TransactionDataBean(ORG2,PROD1,10,new Date(),new Date(System.currentTimeMillis() + 10000));
		tb();tm1.addTransaction(t7);tc();
		tb();tm1.addTransaction(t8);tc();
		tb();result = tm2.getUnprocessed(startDate, endDate);tc();
		assertTrue(result.size() == 2);
		assertTrue(result.get(0).getNodeId() == "node2".hashCode());
		
		tb();tm2.markAsProcessed(startDate, endDate);tc();
		result = tm1.listTransactions(startDate, endDate, WSRAConstants.TRANSACTIONSTATUS_PROCESSING);
		assertTrue(result.size() == 2);
		assertTrue(result.get(0).getNodeId() == "node1".hashCode());
		tb();tm1.markAsProcessed(startDate, endDate);tc();
		result = tm1.listTransactions(startDate, endDate, WSRAConstants.TRANSACTIONSTATUS_PROCESSING);
		assertTrue(result.size() == 0);
		
		tb();tm1.removeTransactions(startDate, endDate);tc();
		result = tm1.listTransactions(startDate, endDate, 0);
		assertTrue(result.size() == 0);
	}


}
