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

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.Transient;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlTransient;

import org.signserver.module.wsra.common.WSRAConstants;
import org.signserver.module.wsra.common.WSRAConstants.OrganizationStatus;
import org.signserver.module.wsra.common.WSRAConstants.OrganizationType;




/**
 * Entity Bean used for storing main organization data used in queries.
 * other data (used for invoicing etc) may be in the the DataBank.
 * 
 * Information stored:
 * <pre>
 * id                        : (PrimaryKey, int) (Not Null)
 * organizationName          : String (Not Null)
 * type                      : int type (Not Null)
 * status                    : int type (Not Null)
 * displayName               : String (Not Null)
 * allowedIssuers            : String (Not Null)
 * allowedCProfiles          : String (Not Null)    
 * users                     : Collection<UserDataBean> one to many relation.
 * comment                   : String 
 * </pre>
 *
 * @author Philip Vendil
 *
 */
@Entity
@Table(name="WSRAOrganizations")
@NamedQueries(
		{@NamedQuery(name="OrganizationDataBean.findByOrganizationName",query="SELECT a from OrganizationDataBean a WHERE a.organizationName=?1 "),
		 @NamedQuery(name="OrganizationDataBean.findAll",query="SELECT a from OrganizationDataBean a ")
		})
public class OrganizationDataBean {


	
   @Id
   @GeneratedValue
   @Column(nullable=false)   
   private int id;
   @Column(nullable=false)
   private int type;
   @Column(nullable=false)
   private int status;
   @Column(nullable=false)
   private String organizationName;
   @Column(nullable=false)
   private String displayName;
   @Column(length=64000)
   private String comment;
   @Column(length=64000,nullable=false)    
   @XmlTransient
   private String allowedIssuersData;
   @Column(length=64000,nullable=false)
   @XmlTransient
   private String allowedCProfilesData;
   @Column(length=64000,nullable=false)
   @XmlTransient
   private String allowedTProfilesData;
   
   @OneToMany(mappedBy="organizationId", fetch=FetchType.LAZY)
   private List<UserDataBean> users;
   
   @OneToMany(mappedBy="organizationId")
   private List<ProductsInOrganizationDataBean> products;
   
   @Transient
   private Set<String> allowedCProfiles;
   @Transient
   private Set<String> allowedTProfiles;
   @Transient
   private Set<String> allowedIssuers;
   @Transient
   private List<DataBankDataBean> relatedData;
   
   /**
    * Empty Constructor
    */
   public OrganizationDataBean() {
	   
   }
   
   /**
    * Constructor used when creating a new OrganizationDataBean
    * @param type the type of organization (customer, partner...) one of
	* the OrganizationType constants
	* @param organizationName the unique name of the organization.
    * @param displayName a human readable name of the user.
    */

   public OrganizationDataBean(OrganizationType type, 
		                       String organizationName, 
		                       String displayName,
		                       Set<String> allowedIssuers,
		                       Set<String> allowedCProfiles,
		                       Set<String> allowedTProfiles) {
	   super();
	   setType(type);
	   this.organizationName = organizationName;
	   this.displayName = displayName;
	   setAllowedIssuers(allowedIssuers);
	   setAllowedCProfiles(allowedCProfiles);
	   setAllowedTProfiles(allowedTProfiles);
	   this.status = WSRAConstants.OrganizationStatus.ACTIVE.getIntValue();
   }

	/**
	 * @return the unique id of the organization.
	 */	
    @XmlTransient
    public  int getId(){
    	return id;
    }

	/**
	 * @param id the unique id of the organization.
	 */
	public void setId(int id) {
		this.id = id;
	}



	/**
	 * @return The comment on this user data entry
	 */
	public String getComment() {
		return comment;
	}


	/**
	 * @param comment The comment on this user data entry
	 */
	public void setComment(String comment) {
		this.comment = comment;
	}

	/**
	 * @return the displayName a human readable name of the user.
	 */
	@XmlElement(required=true)
	public String getDisplayName() {
		return displayName;
	}

	/**
	 * @param displayName a human readable name of the user.
	 */
	public void setDisplayName(String displayName) {
		this.displayName = displayName;
	}


	/**
	 * @return the related users connected with this organization.
	 * @see org.signserver.module.wsra.beans.UserDataBean
	 */
	@XmlElementWrapper(name="users")	
	@XmlElements({@XmlElement(name="user")})
	public List<UserDataBean> getUsers() {
		return users;
	}

	/**
	 * @param users the related users connected with this organization.
	 * @see org.signserver.module.wsra.beans.UserDataBean
	 */
	public void setUsers(List<UserDataBean> users) {
		this.users = users;
	}

	/**
	 * @return the type of organization (customer, partner...) one of
	 * the OrganizationDataBean.TYPE_ constants
	 *
	 */
	@XmlElement(name="type", required=true)
	public String getTypeText() {
		return OrganizationType.findByIntValue(type).toString();
	}

	/**
	 * @param type the type of organization (customer, partner...) one of
	 * the OrganizationDataBean.TYPE_ constants
	 */
	public void setTypeText(String typeText) {
		this.type = OrganizationType.valueOf(typeText).getIntValue();
	}
	
	/**
	 * @return the type of organization (customer, partner...) one of
	 * the OrganizationType constants
	 *
	 */
	@XmlTransient
	public OrganizationType getType() {
		return OrganizationType.findByIntValue(type);
	}

	/**
	 * @param type the type of organization (customer, partner...) one of
	 * the OrganizationType constants
	 */
	public void setType(OrganizationType type) {
		this.type = type.getIntValue();
	}

	/**
	 * @return the the unique name of the organization.
	 */
	@XmlElement(required=true)
	public String getOrganizationName() {
		return organizationName;
	}

	/**
	 * @param organizationName the unique name of the organization.
	 */
	public void setOrganizationName(String organizationName) {
		this.organizationName = organizationName;
	}

	/**
	 * @return the products a collection of all products this organization is
	 * interested of (not the same as bought, but they have a price list)
	 */
	public List<ProductsInOrganizationDataBean> getProducts() {
		return products;
	}

	/**
	 * @param products the products a collection of all products this organization is
	 * interested of (not the same as bought, but they have a price list)
	 */
	public void setProducts(List<ProductsInOrganizationDataBean> products) {
		this.products = products;
	}
	
	/**
	 * @return the allowed issuers the organization is authorized to, never null
	 */
	@XmlElementWrapper(name="allowedIssuers", required=true)
	@XmlElements({@XmlElement(name="allowedIssuer")})
	public Set<String> getAllowedIssuers() {		
		if(allowedIssuers == null && allowedIssuersData != null){
			allowedIssuers = new HashSet<String>();
			String[] allIssuers = allowedIssuersData.split(",");

			for(String issuer : allIssuers){
				if(issuer.length() >0){
					allowedIssuers.add(issuer);
				}
			}
		}
		
		return allowedIssuers;
	}

	/**
	 * @param the allowed issuers the organization is authorized to, never null
	 */
	public void setAllowedIssuers(Set<String> allowedIssuers) {
		String allIssuers = "";
		for(String issuer : allowedIssuers){
			allIssuers += issuer + ",";
		}
		this.allowedIssuersData = allIssuers;
		this.allowedIssuers = allowedIssuers;
	}

	/**
	 * @return the allowed certificate profiles the organization is authorized to, never null
	 */	
	@XmlElementWrapper(name="allowedCertificateProfiles",required=true)
	@XmlElements({@XmlElement(name="allowedCertificateProfile")})
	public Set<String> getAllowedCProfiles() {			
		if(allowedCProfiles == null && allowedCProfilesData != null){
			allowedCProfiles = new HashSet<String>();
			String[] allCProfiles = allowedCProfilesData.split(",");			
			for(String cProfile : allCProfiles){
				if(cProfile.length() >0){
					allowedCProfiles.add(cProfile);
				}
			}
		}
		
		return allowedCProfiles;
	}

	/**
	 * @param the allowed certificate profiles the organization is authorized to, never null
	 */
	public void setAllowedCProfiles(Set<String> allowedCProfiles) {
		String allCProfiles = "";
		for(String cProfile : allowedCProfiles){
			allCProfiles += cProfile + ",";
		}
		this.allowedCProfilesData = allCProfiles;
		this.allowedCProfiles = allowedCProfiles;
	}
	
	/**
	 * @return the allowed certificate profiles the organization is authorized to, never null
	 */	
	@XmlElementWrapper(name="allowedTokenProfiles",required=true)
	@XmlElements({@XmlElement(name="allowedTokenProfile")})
	public Set<String> getAllowedTProfiles() {			
		if(allowedTProfiles == null && allowedTProfilesData != null){
			allowedTProfiles = new HashSet<String>();
			String[] allTProfiles = allowedTProfilesData.split(",");			
			for(String tProfile : allTProfiles){
				if(tProfile.length() >0){
					allowedTProfiles.add(tProfile);
				}
			}
		}
		
		return allowedTProfiles;
	}

	/**
	 * @param the allowed token profiles the organization is authorized to, never null
	 */
	public void setAllowedTProfiles(Set<String> allowedTProfiles) {
		String allTProfiles = "";
		for(String tProfile : allowedTProfiles){
			allTProfiles += tProfile + ",";
		}
		this.allowedTProfilesData = allTProfiles;
		this.allowedTProfiles = allowedTProfiles;
	}

	/**
	 * The status of the organization
	 * @return one of WSRAConstants.ORGANIZATIONSTATUS_ constants
	 */
	@XmlElement(name="status", required=true)
	public String getStatusText() {
		return OrganizationStatus.findByIntValue(status).toString();
	}

	/**
	 * Set the status of the organization
	 * @param status one of WSRAConstants.ORGANIZATIONSTATUS_ constants
	 */
	public void setStatusText(String statusText) {		
		this.status = OrganizationStatus.valueOf(statusText).getIntValue();
	}

	/**
	 * The related data stored in the data bank.
	 * This data should be managed separately.
	 * 
	 */
	@XmlElementWrapper(name="relatedData")
	@XmlElements({@XmlElement(name="property")})
	public List<DataBankDataBean> getRelatedData() {
		return relatedData;
	}

	/**
	 * The related data stored in the data bank.
	 * This data should be managed separately.
	 * 
	 */
	public void setRelatedData(List<DataBankDataBean> relatedData) {
		this.relatedData = relatedData;
	}

	/**
	 * @return the status
	 */
	@XmlTransient
	public OrganizationStatus getStatus() {
		return OrganizationStatus.findByIntValue(status);
	}

	/**
	 * @param status the status to set
	 */
	public void setStatus(OrganizationStatus status) {
		this.status = status.getIntValue();
	}


}
