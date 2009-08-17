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
 
package org.signserver.module.wsra.beans;

import java.util.List;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;

/**
 * A Special bean used to backup and restore the contents of the database.
 * 
 * 
 * @author Philip Vendil 29 okt 2008
 *
 * @version $Id$
 */
@XmlRootElement(name="wsradata")
public class BackupRestoreBean {
	
	@XmlElementWrapper(name="organizations")
	@XmlElements({@XmlElement(name="organization")})
	private List<OrganizationDataBean> organizations;
	@XmlElementWrapper(name="products")
	@XmlElements({@XmlElement(name="product")})
	private List<ProductDataBean> products;
	@XmlElementWrapper(name="pricing")
	@XmlElements({@XmlElement(name="price")})
	private List<PricingDataBean> pricing;
	@XmlElementWrapper(name="productMappings")
	@XmlElements({@XmlElement(name="productMapping")})
	private List<ProductMappingBean> productMappings;
	
	

	public BackupRestoreBean() {
		super();		
	}
	/**
	 * @return the organizations
	 */
	@XmlTransient
	public List<OrganizationDataBean> getOrganizations() {
		return organizations;
	}
	/**
	 * @param organizations the organizations to set
	 */	
	public void setOrganizations(List<OrganizationDataBean> organizations) {
		this.organizations = organizations;
	}
	/**
	 * @return the products
	 */
	@XmlTransient
	public List<ProductDataBean> getProducts() {
		return products;
	}
	/**
	 * @param products the products to set
	 */
	public void setProducts(List<ProductDataBean> products) {
		this.products = products;
	}
	/**
	 * @return the pricing
	 */
	@XmlTransient
	public List<PricingDataBean> getPricing() {
		return pricing;
	}
	/**
	 * @param pricing the pricing to set
	 */
	public void setPricing(List<PricingDataBean> pricing) {
		this.pricing = pricing;
	}
	/**
	 * @return the productMappings
	 */
	@XmlTransient
	public List<ProductMappingBean> getProductMappings() {
		return productMappings;
	}
	/**
	 * @param productMappings the productMappings to set
	 */
	public void setProductMappings(List<ProductMappingBean> productMappings) {
		this.productMappings = productMappings;
	}

}
