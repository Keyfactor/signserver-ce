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

import java.io.File;
import java.io.IOException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.signserver.module.wsra.beans.BackupRestoreBean;
import org.signserver.module.wsra.beans.OrganizationDataBean;
import org.signserver.module.wsra.beans.ProductDataBean;
import org.signserver.module.wsra.beans.UserDataBean;

/**
 * Class in charge of reading and storing XML serialization
 * data of database configuration.
 * 
 * 
 * @author Philip Vendil 29 okt 2008
 *
 * @version $Id$
 */

public class DataFileParser {
	
	private static JAXBContext jaxbContext = null;
	   
	BackupRestoreBean data = null;
	
	public DataFileParser(String filename) throws IOException, JAXBException{
		jaxbContext = JAXBContext.newInstance(BackupRestoreBean.class, OrganizationDataBean.class,UserDataBean.class,ProductDataBean.class);
		
		Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
		data = new BackupRestoreBean();		
		data = (BackupRestoreBean) unmarshaller.unmarshal(new File(filename));		
	}
	
	public DataFileParser(BackupRestoreBean data) throws IOException, JAXBException{
		jaxbContext = JAXBContext.newInstance(BackupRestoreBean.class);
		
		this.data = data;
	}
	
	public BackupRestoreBean getData(){
		return data;
	}
	
	public void dumpData(String filename) throws JAXBException{
		Marshaller marshaller = jaxbContext.createMarshaller();
		marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT ,
                new Boolean(true));

		marshaller.marshal(data, new File(filename));
	}
	

}
