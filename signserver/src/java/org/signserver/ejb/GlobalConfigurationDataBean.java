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

import javax.ejb.CreateException;

import org.ejbca.core.ejb.BaseEntityBean;

/**
 * Entity Bean storing the global configuration dynamically
 * 
 * Information stored:
 * <pre>
 * propertyKey   : String (PrimaryKey)
 * propertyValue : String 
 * </pre>
 *
 * @version $Id: GlobalConfigurationDataBean.java,v 1.1 2007-02-27 16:18:19 herrvendil Exp $
 *
 * @ejb.bean description="Entity Bean storing the global configuration in database."
 * display-name="GlobalConfigurationDataBean"
 * name="GlobalConfigurationData"
 * view-type="local"
 * type="CMP"
 * reentrant="False"
 * cmp-version="2.x"
 * transaction-type="Container"
 * schema="GlobalConfigurationDataBean"
 * primkey-field="propertyKey"
 * 
 * @ejb.transaction type="Required"
 *
 * @ejb.permission role-name="InternalUser"
 *
 * @ejb.finder
 *   description="findAll"
 *   signature="java.util.Collection findAll()"
 *   query="SELECT OBJECT(a) from GlobalConfigurationDataBean a"
 *
 * @ejb.home
 * generate="local"
 * local-extends="javax.ejb.EJBLocalHome"
 * local-class="org.signserver.ejb.GlobalConfigurationDataLocalHome"
 *
 * @ejb.interface
 * generate="local"
 * local-extends="javax.ejb.EJBLocalObject"
 * local-class="org.signserver.ejb.GlobalConfigurationDataLocal"
 *
 *
 * @jonas.jdbc-mapping
 *   jndi-name="${datasource.jndi-name}"
 */
public abstract class GlobalConfigurationDataBean extends BaseEntityBean {

    //private static final Logger log = Logger.getLogger(GlobalConfigurationDataBean.class);

    
  
    /**
     * The key of the property
     *
     * @return propertyKey with the scope in the beginning (node. or glob.)
     * @ejb.persistence
     * @ejb.interface-method
     * @ejb.pk-field 
     */
    public abstract String getPropertyKey();

    /**
     * 
     * @param propertyKey with the scope in the beginning (node. or glob.)
     * @ejb.persistence
     */
    public abstract void setPropertyKey(String propertyKey);
   
    /**
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract String getPropertyValue();

    /**
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract void setPropertyValue(String propertyValue);    
    

    //
    // Fields required by Container
    //

    /**
     * Entity Bean holding info about a global property
     * 
     *
     * @return primary key
     * @ejb.create-method
     */
    public String ejbCreate(String propertyKey, String propertyValue)
        throws CreateException {

    	this.setPropertyKey(propertyKey);
    	this.setPropertyValue(propertyValue);
    	
        return propertyKey;
    }

    /**
     * required method, does nothing
     */
    public void ejbPostCreate(String propertyKey, String propertyValue) {
        // Do nothing. Required.
    }



}
