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

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.module.wsra.beans.BackupRestoreBean;
import org.signserver.module.wsra.beans.DataBankDataBean;
import org.signserver.module.wsra.beans.OrganizationDataBean;
import org.signserver.module.wsra.beans.PricingDataBean;
import org.signserver.module.wsra.beans.ProductDataBean;
import org.signserver.module.wsra.beans.ProductMappingBean;
import org.signserver.module.wsra.beans.ProductsInOrganizationDataBean;
import org.signserver.module.wsra.beans.TokenDataBean;
import org.signserver.module.wsra.beans.UserDataBean;
import org.signserver.module.wsra.common.WSRAConstants;
import org.signserver.server.cryptotokens.ICryptoToken;

/**
 * Class in charge of doing "bulk" configuration and dump
 * of database data.
 * 
 * @author Philip Vendil 11 okt 2008
 *
 * @version $Id$
 */

public class DataConfigurationManager {
	
	public enum Type{
		ALL,
		ORGANIZATIONS,
		PRODUCTS,
		PRICES,
		PRODUCTMAPPINGS
	}
	
	@SuppressWarnings("unused")
	private Logger log = Logger.getLogger(this.getClass());
	private DBManagers db;
    private boolean tokenImportSupported = false;
	private boolean transationActive;		
	
	/**
	 * Constructor used for external import of data.
	 * 
	 * Instances of this constructor cannot import
	 * Tokens.
	 * 
	 * @param workerEntityManager
	 * @throws SignServerException
	 */
	public DataConfigurationManager(EntityManager workerEntityManager) throws SignServerException{		
		db = new DBManagers(new WorkerConfig(),workerEntityManager,
				new HashSet<Class<?>>(),new HashSet<Class<?>>(),null,null,""); 
	}
	
	/**
	 * Constructor used for external import of data.
	 * 
	 * 
	 * @param workerEntityManager
	 * @throws SignServerException
	 */
	public DataConfigurationManager(WorkerConfig wc, 
	          EntityManager workerEntityManager,
	          Set<Class<?>> availableTokenProfileClasses,
	          Set<Class<?>> availableAuthTypeClasses,
	          ICryptoToken ct,
	          Certificate certificate,
	          String nodeId) throws SignServerException{		
		db = new DBManagers(wc,workerEntityManager,
				availableTokenProfileClasses,availableAuthTypeClasses,ct,certificate,nodeId);
		tokenImportSupported = true;
		transationActive = workerEntityManager.getTransaction().isActive();
	}
	
	public BackupRestoreBean dumpConfiguration(Type type, boolean includeUsers, boolean includeTokens) throws SignServerException{
		BackupRestoreBean retval = new BackupRestoreBean();
		
		if(type.equals(Type.ALL) || type.equals(Type.ORGANIZATIONS) ){
			retval.setOrganizations(dumpOrganizations(includeUsers, includeTokens));
		}
		if(type.equals(Type.ALL) || type.equals(Type.PRICES) ){
			retval.setPricing(dumpPricing());
		}
		if(type.equals(Type.ALL) || type.equals(Type.PRODUCTS) ){
			retval.setProducts(dumpProducts());
		}
		if(type.equals(Type.ALL) || type.equals(Type.PRODUCTMAPPINGS) ){
			retval.setProductMappings(dumpProductMappings());
		}
		
		return retval;
	}
	
	private List<ProductMappingBean> dumpProductMappings() throws SignServerException {
		ProductMapper pMapper = new ProductMapper(db.dbm);
		return pMapper.getProductMappings();
	}

	public void storeConfiguration(Type type, BackupRestoreBean config, boolean includeUsers, boolean includeTokens) throws SignServerException{
		if(type.equals(Type.ALL) || type.equals(Type.PRICES) ){
			storePrices(config.getPricing());
		}
		if(type.equals(Type.ALL) || type.equals(Type.PRODUCTS) ){
			storeProducts(config.getProducts());
		}
		
		if(type.equals(Type.ALL) || type.equals(Type.ORGANIZATIONS) ){
			storeOrganizations(config.getOrganizations(),includeUsers, includeTokens);
		}
		
		if(type.equals(Type.ALL) || type.equals(Type.PRODUCTMAPPINGS) ){
			storeProductMappings(config.getProductMappings());
		}

	}

	private void storeProductMappings(List<ProductMappingBean> productMappings) throws SignServerException {
		ProductMapper pMapper = new ProductMapper(db.dbm);
		transactionBegin();
		pMapper.setProductMappings(productMappings);
		transactionCommit();
		log.info("Product with mappings added to database.");
		
	}

	private void storeProducts(List<ProductDataBean> products) {
		if(products != null){
			for(ProductDataBean prod : products){
				transactionBegin();
				db.pm.editProduct(prod);				
				transactionCommit();
				log.info("Product with number " + prod.getProductNumber() + " stored in database.");
			}		
		}
	}

	private void storePrices(List<PricingDataBean> pricing) {
		if(pricing != null){
			for(PricingDataBean price : pricing){
				transactionBegin();
				db.pm.editPrice(price);
				transactionCommit();
				log.info("Priceclass " + price.getPriceClass() + " stored in database.");
			}		
		}
	}

	private void storeOrganizations(List<OrganizationDataBean> organizations,
			boolean includeUsers, boolean includeTokens) throws SignServerException {
		if(organizations != null){
			for(OrganizationDataBean org : organizations){
				transactionBegin();				
				int orgId = db.om.editOrganization(org);
				
				// Remove related data
				List<DataBankDataBean> existingRelatedData = db.dbm.getRelatedProperies(WSRAConstants.DATABANKTYPE_ORGANIZATION, orgId);
				for(DataBankDataBean dbd : existingRelatedData){					
					db.dbm.removeRelatedPropery(dbd.getType(),dbd.getRelatedId(), dbd.getKey());
				}
				
				List<DataBankDataBean> relatedData = org.getRelatedData();
				if(relatedData != null){
					for(DataBankDataBean dbd : relatedData){					
						db.dbm.setRelatedProperty(WSRAConstants.DATABANKTYPE_ORGANIZATION, orgId, dbd.getKey(), dbd.getValue());
					}
				}
				
				List<ProductsInOrganizationDataBean> existingProducts = db.om.findProductsInOrganization(orgId);
				for(ProductsInOrganizationDataBean p : existingProducts){					
					db.om.removeProductInOrganization(orgId, p.getProductId());
				}
				
				List<ProductsInOrganizationDataBean> products = org.getProducts();
				if(products != null){
					for(ProductsInOrganizationDataBean p : products){	
						p.setOrganizationId(orgId);
						db.om.editProductInOrganization(p);
					}
				}
				
				if(includeUsers){
					List<UserDataBean> users = org.getUsers();
					if(users != null){
						for(UserDataBean user : users){							
							UserDataBean existingUser = db.um.findUser(user.getUserName(), orgId);
							
							user.setOrganizationId(orgId);
							db.um.editUser(user);
						
							
							if(includeTokens && tokenImportSupported){
								Collection<TokenDataBean> tokens = user.getTokens();
								if(tokens != null){
									for(TokenDataBean t : tokens){
	                                  t.setUserId(existingUser.getId());
	                                  t.setOrganizationId(orgId);	                                  
	                                  db.tm.editToken(t);
									}
								}
							}
						}
					}
				}
			
				
				transactionCommit();
				log.info("Organization with name " + org.getOrganizationName() + " stored in database.");
			}
			
		}
		
	}

	private List<PricingDataBean> dumpPricing() {
		return db.pm.listPrices(null);		
	}

	private List<ProductDataBean> dumpProducts() {		
		return db.pm.listProducts(null);
	}

	/**
	 * Method used to dump all configured organizations
	 * 
	 * @param includeUsers if users should be included in the dump
	 * @param includeTokens if tokens should be included in dump, if
	 * includeUsers is false is this setting ineffective.
	 * @return a list of organizations.
	 */
	private List<OrganizationDataBean> dumpOrganizations(boolean includeUsers, boolean includeTokens){
		List<OrganizationDataBean> orgs = db.om.listOrganizations();
		for(OrganizationDataBean org : orgs){
			org.setRelatedData(db.dbm.getRelatedProperies(WSRAConstants.DATABANKTYPE_ORGANIZATION, org.getId()));
			
			for(ProductsInOrganizationDataBean podb : org.getProducts()){
				podb = db.om.findProductInOrganization(org.getId(), podb.getProductId());
			}
			
			if(includeUsers){
				for(UserDataBean udb : org.getUsers()){
					if(!includeTokens){
						udb.setTokens(new ArrayList<TokenDataBean>());
					}
				}
			}else{
				org.setUsers(new ArrayList<UserDataBean>());
			}
		}
		
		return orgs;
	}
	
	private void transactionBegin(){
	   if(!transationActive){
		   db.workerEntityManager.getTransaction().begin();
	   }
	}
	private void transactionCommit(){
		if(!transationActive){
			db.workerEntityManager.getTransaction().commit();
		}
	}
	
	@SuppressWarnings("unused")
	private void transactionRollback(){
		if(!transationActive){
			db.workerEntityManager.getTransaction().rollback();
		}
	}

}
