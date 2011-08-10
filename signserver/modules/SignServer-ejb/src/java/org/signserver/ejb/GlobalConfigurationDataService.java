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

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.Query;

/**
 * Entity Service class that acts as migration layer for
 * the old Home Interface for the GlobalConfigurationData Entity Bean
 * 
 * Contains about the same methods as the EJB 2 entity beans home interface.
 *
 * @version $Id$
 */
class GlobalConfigurationDataService {

    private EntityManager em;

    public GlobalConfigurationDataService(EntityManager em) {
        this.em = em;
    }

    public void setGlobalProperty(String completekey, String value) {
        GlobalConfigurationDataBean data = em.find(GlobalConfigurationDataBean.class, completekey);
        if (data == null) {
            data = new GlobalConfigurationDataBean();
            data.setPropertyKey(completekey);
            data.setPropertyValue(value);
            em.persist(data);
        } else {
            data.setPropertyValue(value);
        }
    }

    public boolean removeGlobalProperty(String completekey) {
        boolean retval = false;
        GlobalConfigurationDataBean data = em.find(GlobalConfigurationDataBean.class, completekey);
        if (data != null) {
            em.remove(data);
            retval = true;
        }
        return retval;
    }

    @SuppressWarnings("unchecked")
    public List<GlobalConfigurationDataBean> findAll() {
        Query query = em.createQuery("SELECT e from GlobalConfigurationDataBean e");

        return (List<GlobalConfigurationDataBean>) query.getResultList();
    }
}
