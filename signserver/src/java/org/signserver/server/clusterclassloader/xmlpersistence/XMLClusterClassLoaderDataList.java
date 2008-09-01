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
package org.signserver.server.clusterclassloader.xmlpersistence;

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;


/**
 * 
 * XML binding class for a collection of resources (XMLCluserClassLoaderDataBean)
 * 
 * @author Philip Vendil 15 maj 2008
 *
 */


@XmlRootElement(name="resources")
public class XMLClusterClassLoaderDataList  {
	  
	    public XMLClusterClassLoaderDataList(){
	    	datas = new ArrayList<XMLClusterClassLoaderDataBean>();
	    }
	
	    @XmlElements({@XmlElement(name="resource")})
	    private List<XMLClusterClassLoaderDataBean> datas;
	    
	    
	    public void add(XMLClusterClassLoaderDataBean data){
	    	datas.add(data);
	    }
	    
	    @XmlTransient
	    public List<XMLClusterClassLoaderDataBean> getList(){
	    	return datas;
	    }

}
