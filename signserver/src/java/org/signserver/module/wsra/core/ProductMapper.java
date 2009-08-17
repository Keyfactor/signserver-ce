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
import java.util.List;

import org.signserver.common.SignServerException;
import org.signserver.module.wsra.beans.DataBankDataBean;
import org.signserver.module.wsra.beans.ProductMappingBean;
import org.signserver.module.wsra.common.WSRAConstants;

/**
 * Class in charge of mapping WS call events to product numbers.
 * The configuration is done in the databank.
 * 
 * The mapping configuration should have the following form using
 * the type WSRAConstants.DATABANK_PRODUCTMAPPING
 * 
 * <p>
 * 'MAPPINGNAME'.'EVENT'.'TOKENPROFILE'.'CERTPROFILE'='PRODUCTNUMBER'
 * <p>
 * Where event is a custom defined string, example CERTGEN, token profile  
 * and certificate profile is a existing profiles in the system.
 * <p>
 * Any event,token or cert profile can have the * value which indicates all
 * values. 
 * <p>
 * Example of values:<br>
 * MAPPING1.CERTREV.*.*=PROD1<br>
 * MAPPING2.*.JKSTOKENPROFILE.*=PROD2<br>
 * <p>
 * It's undefined which product number used if an event matches more
 * than one mappings, so make sure to set it up properly.
 * <p>
 * @author Philip Vendil 25 okt 2008
 *
 * @version $Id$
 */

public class ProductMapper {
		
	private List<ProductMappingBean> mappings = null;
	private DataBankManager dbm;
	
	/**
	 * Initializes the product mapper from the database configuration
	 * @param dbm the data bank manager
	 * @throws SignServerException if error could be found in worker configuration.
	 */
	public ProductMapper(DataBankManager dbm) throws SignServerException{
         this.dbm = dbm;
	}
	
	/**
	 * Method that finds the product number from the configured
	 * set of product mappings.
	 * 
	 * @param eventType a custom defined type of event
	 * @param tokenProfile a token profile used in the system.
	 * @param cProfile a certificate profile used in the system.
	 * @return the mapped product number of null if no product number
	 * could be found.
	 * @throws SignServerException if product mappings is miss configured
	 */
	public String getProductNumber(String eventType, String tokenProfile, String cProfile) throws SignServerException{
		ProductMappingBean reqPM = new ProductMappingBean(null,eventType,tokenProfile,cProfile,null);
		for(ProductMappingBean pm : getProductMappings()){
			if(pm.equals(reqPM)){
				return pm.getProductNumber();
			}
		}
		
		return null;
	}


	/**
	 * Method that returns all current configured ProductMappings
	 * @throws SignServerException if product mappings is miss configured
	 */
	public List<ProductMappingBean> getProductMappings() throws SignServerException{
		if(mappings == null){
			mappings = new ArrayList<ProductMappingBean>();
			List<DataBankDataBean> prodMappings = dbm.getTypeProperies(WSRAConstants.DATABANKTYPE_PRODUCTMAPPING);
			for(DataBankDataBean dbd : prodMappings){
				String key = dbd.getKey();			
				String[] values = key.split("\\.");
				if(values.length < 4){
					throw new SignServerException("Error in worker configuration, check product mapping : " + key);
				}
				ProductMappingBean pm = new ProductMappingBean(values[0],values[1],values[2],values[3],dbd.getValue());
				mappings.add(pm);			
			}
		}
		return mappings;
	}
	
	/**
	 * Adds a list of product mappings to the database
	 * @param newMaps
	 */
	public void setProductMappings(List<ProductMappingBean> newMaps){
       for(ProductMappingBean pmb : newMaps){    	   
    	   dbm.setProperty(WSRAConstants.DATABANKTYPE_PRODUCTMAPPING, pmb.getKey(), pmb.getProductNumber());
       }	
       mappings = null;
	}
	
	/**
	 * Method that removes a product mapping from the data bank
	 * @param mappingName the unique identifier of mapping.
	 * @throws SignServerException if current db data is missconfigured.
	 */
	public void removeProductMapping(String mappingName) throws SignServerException{
		for(ProductMappingBean pmb : getProductMappings()){
			if(pmb.getMappingName().equals(mappingName)){
				dbm.removePropery(WSRAConstants.DATABANKTYPE_PRODUCTMAPPING, pmb.getKey());
				break;
			}	    	   	    	  
		}
		mappings = null;
	}
}
