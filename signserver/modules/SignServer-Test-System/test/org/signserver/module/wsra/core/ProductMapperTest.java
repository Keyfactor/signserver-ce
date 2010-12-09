package org.signserver.module.wsra.core;

import java.util.ArrayList;
import java.util.List;

import org.signserver.common.SignServerException;
import org.signserver.module.wsra.beans.ProductMappingBean;

public class ProductMapperTest extends CommonManagerT {
	private static DataBankManager dm = null;
	
	protected void setUp() throws Exception {
		super.setUp();
		if(dm == null){
	          dm = new DataBankManager(workerEntityManager);		  		
		}
	}
	
	public void test01ProductMapper() throws SignServerException{
		ArrayList<ProductMappingBean> pmaps = new ArrayList<ProductMappingBean>();
		pmaps.add(new ProductMappingBean("MAPPING1","GENCERT","TPROF1","CPROF1","Artnr1"));
		pmaps.add(new ProductMappingBean("MAPPING2","*","TPROF2","*","Artnr2"));
		pmaps.add(new ProductMappingBean("MAPPING3","CHECKREV","*","*","Artnr3"));	
		
		ProductMapper pm = new ProductMapper(dm);
		
		tb();pm.setProductMappings(pmaps);tc();
		
		String artNum = pm.getProductNumber("GENCERT", "TPROF1", "CPROF1");
		assertTrue(artNum.equals("Artnr1"));
		
		artNum = pm.getProductNumber("ABDC", "TPROF2", "CPROFNOEX");
		assertTrue(artNum.equals("Artnr2"));
		
		artNum = pm.getProductNumber("CHECKREV", "TPROF2123", "CPROFNOEX");
		assertTrue(artNum.equals("Artnr3"));
		
		artNum = pm.getProductNumber("NOEXIST", "TPROF2123", "CPROFNOEX");
		assertNull(artNum);
		
		tb();pm.removeProductMapping("MAPPING3");tc();
		List<ProductMappingBean> list = pm.getProductMappings();
		assertTrue(list.size()== 2);

	}

}
