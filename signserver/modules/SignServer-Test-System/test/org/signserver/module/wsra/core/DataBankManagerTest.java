package org.signserver.module.wsra.core;

import org.signserver.module.wsra.common.WSRAConstants;

public class DataBankManagerTest extends CommonManagerT {
	
	private static DataBankManager dm = null;

	
	protected void setUp() throws Exception {
		super.setUp();
		if(dm == null){
          dm = new DataBankManager(workerEntityManager);		  		
		}
	}
	
	public void test01DataBankManager() throws Exception{
		
		tb();dm.setProperty(WSRAConstants.DATABANKTYPE_PRICE, "key1", "value1");tc();
		tb();dm.setProperty(WSRAConstants.DATABANKTYPE_PRICE, "key2", "value2");tc();
		tb();dm.setProperty(WSRAConstants.DATABANKTYPE_PRICE, "key3", "value3");tc();
		tb();dm.setProperty(WSRAConstants.DATABANKTYPE_GENERAL, "key1", "value4");tc();
		tb();dm.setProperty(WSRAConstants.DATABANKTYPE_GENERAL, "key2", "value5");tc();
		
		assertTrue(dm.getAllProperies().size() == 5);		
		assertTrue(dm.getTypeProperies(WSRAConstants.DATABANKTYPE_PRICE).size() == 3);
		assertTrue(dm.getTypeProperies(WSRAConstants.DATABANKTYPE_GENERAL).size() == 2);
		assertTrue(dm.getTypeProperies(WSRAConstants.DATABANKTYPE_ORGANIZATION).size() == 0);
		assertTrue(dm.getProperty(WSRAConstants.DATABANKTYPE_PRICE, "key2").equals("value2"));
		
		tb();dm.removePropery(WSRAConstants.DATABANKTYPE_PRICE, "key3");tc();
		assertTrue(dm.getAllProperies().size() == 4);		
		assertTrue(dm.getTypeProperies(WSRAConstants.DATABANKTYPE_PRICE).size() == 2);
		assertNull(dm.getProperty(WSRAConstants.DATABANKTYPE_PRICE, "key3"));
		tb();dm.removePropery(WSRAConstants.DATABANKTYPE_PRICE, "key3");tc();
	}
	
	public void test01RelatedData() throws Exception{
		
		tb();dm.setRelatedProperty(WSRAConstants.DATABANKTYPE_ORGANIZATION,111, "key1", "value1");tc();
		tb();dm.setRelatedProperty(WSRAConstants.DATABANKTYPE_ORGANIZATION,111, "key2", "value2");tc();
		tb();dm.setRelatedProperty(WSRAConstants.DATABANKTYPE_ORGANIZATION,111, "key3", "value3");tc();
		
		
		assertTrue(""+dm.getRelatedProperies(WSRAConstants.DATABANKTYPE_ORGANIZATION,111).size(), dm.getRelatedProperies(WSRAConstants.DATABANKTYPE_ORGANIZATION,111).size() == 3);		

	}
	

}
