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
 

package org.signserver.ejb;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.Table;

/**
 * Entity Bean storing the global configuration dynamically
 * 
 * Information stored:
 * <pre>
 * propertyKey   : String (PrimaryKey)
 * propertyValue : String 
 * </pre>
 *
 * @version $Id$
 *
 */
@Entity
@Table(name="GlobalConfigurationData")
public class GlobalConfigurationDataBean  {

	@Id
	private String propertyKey;
    @Lob
	@Column(length=1048576)
	private String propertyValue;
 
    public String getPropertyKey(){
    	return propertyKey;
    }
    public void setPropertyKey(String propertyKey){
    	this.propertyKey = propertyKey;
    }
   

    public String getPropertyValue(){
    	return propertyValue;
    }
    public void setPropertyValue(String propertyValue){
    	this.propertyValue = propertyValue;
    }
    

 





}
