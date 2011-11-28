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

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlTransient;


/**
 * Value object for a product mapping used for internal logic
 * and xml serialization.
 * 
 * This isn't an entity bean, it's data is stored in data bank
 * using the ProductMapper class.
 * 
 * @author Philip Vendil 31 okt 2008
 *
 * @version $Id$
 */

public class ProductMappingBean {
	
		private String mappingName = null;
		private String eventType = null;
		private String tokenProfile = null;
		private String cProfile = null;
		private String productNumber = null;
		
		public ProductMappingBean(){}
		

		/**
		 * @return the mappingName only used to identify mapping.
		 */
		@XmlElement(required=true)
		public String getMappingName() {
			return mappingName;
		}



		/**
		 * @param mappingName the mappingName to set, only used to identify mapping.
		 */
		public void setMappingName(String mappingName) {
			this.mappingName = mappingName;
		}

		/**
		 * @return the eventType
		 */
		public String getEventType() {
			return eventType;
		}



		/**
		 * @param eventType the eventType to set
		 */
		public void setEventType(String eventType) {
			this.eventType = eventType;
		}



		/**
		 * @return the tokenProfile
		 */
		public String getTokenProfile() {
			return tokenProfile;
		}



		/**
		 * @param tokenProfile the tokenProfile to set
		 */
		public void setTokenProfile(String tokenProfile) {
			this.tokenProfile = tokenProfile;
		}



		/**
		 * @return the certificateProfile
		 */
		public String getCProfile() {
			return cProfile;
		}



		/**
		 * @param profile the certificateProfile to set
		 */
		public void setCProfile(String profile) {
			cProfile = profile;
		}



		/**
		 * @return the productNumber that is related
		 */
		@XmlElement(required=true)
		public String getProductNumber() {
			return productNumber;
		}



		/**
		 * @param productNumber the productNumber that is related
		 */
		public void setProductNumber(String productNumber) {
			this.productNumber = productNumber;
		}



		public ProductMappingBean(String mappingName, String eventType, String tokenProfile, String cProfile, String productNumber) {
			super();
			this.mappingName = mappingName;
			if(eventType != null && !eventType.trim().equals("*")){
				this.eventType = eventType;
			}
			if(tokenProfile != null && !tokenProfile.trim().equals("*")){
				this.tokenProfile = tokenProfile;
			}
			if(cProfile != null && !cProfile.trim().equals("*")){
				this.cProfile = cProfile;
			}
			
			this.productNumber = productNumber;
		}

		public boolean equals(Object obj) {
			boolean retval = true;
			
			if(!(obj instanceof ProductMappingBean)){
				return false;
			}
			
			ProductMappingBean p = (ProductMappingBean) obj; 
			
			if(eventType != null){
				if(p.eventType == null || !eventType.equals(p.eventType)){
					return false;
				}
			}			
			if(tokenProfile != null){
				if(p.tokenProfile == null || !tokenProfile.equals(p.tokenProfile)){
					return false;
				}
			}			
			if(cProfile != null){
				if(p.cProfile == null || !cProfile.equals(p.cProfile)){
					return false;
				}
			}
			return retval;
		}


		/**
		 * 
		 * @return a key representation used for storing
		 * in the data bank.
		 */
        @XmlTransient
		public String getKey(){
			String key = mappingName;
			if(eventType== null || eventType.trim().equals('*')){
				key += ".*";
			}else{
				key += "." + eventType;
			}
			if(tokenProfile== null || tokenProfile.trim().equals('*')){
				key += ".*";
			}else{
				key += "." + tokenProfile;
			}
			if(cProfile== null || cProfile.trim().equals('*')){
				key += ".*";
			}else{
				key += "." + cProfile;
			}
			return key;
		}

		
	
}
