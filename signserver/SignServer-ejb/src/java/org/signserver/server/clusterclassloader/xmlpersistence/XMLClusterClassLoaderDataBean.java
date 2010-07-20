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

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlType;

import org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean;

/**
 * Data bean used to marshall into XML file for simple persistence
 * 
 * @author Philip Vendil 15 maj 2008
 *
 */

@XmlType(name="resource")
public class XMLClusterClassLoaderDataBean implements
		IClusterClassLoaderDataBean {


	   private int id;
	   private String resourceName;	   
	   private String implInterfaces;
	   private int version;    
	   private String type;
	   private String jarName;
	   private String moduleName;
	   private String part;
	   private byte[] resourceData;
	   private long timeStamp;
	   private String description;
	   private String comment;

	  
	    /* (non-Javadoc)
		 * @see org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean#getId()
		 */	
	   @XmlAttribute
	    public  int getId(){
	    	return id;
	    }

		/* (non-Javadoc)
		 * @see org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean#setId(int)
		 */
		public void setId(int id) {
			this.id = id;
		}

		/* (non-Javadoc)
		 * @see org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean#getResourceName()
		 */
		@XmlAttribute
		public String getResourceName() {
			return resourceName;
		}


		/* (non-Javadoc)
		 * @see org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean#setResourceName(java.lang.String)
		 */
		public void setResourceName(String resourceName) {
			this.resourceName = resourceName;
		}


		/* (non-Javadoc)
		 * @see org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean#getImplInterfaces()
		 */
		public String getImplInterfaces() {
			return implInterfaces;
		}


		/* (non-Javadoc)
		 * @see org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean#setImplInterfaces(java.lang.String)
		 */
		public void setImplInterfaces(String implInterfaces) {
			this.implInterfaces = implInterfaces;
		}


		/* (non-Javadoc)
		 * @see org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean#getVersion()
		 */
		@XmlAttribute
		public int getVersion() {
			return version;
		}

		
		/* (non-Javadoc)
		 * @see org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean#getType()
		 */
		@XmlAttribute
		public String getType() {
			return type;
		}

		/* (non-Javadoc)
		 * @see org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean#setType(java.lang.String)
		 */
		public void setType(String type) {
			this.type = type;
		}

		/* (non-Javadoc)
		 * @see org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean#setVersion(int)
		 */
		public void setVersion(int version) {
			this.version = version;
		}


		/* (non-Javadoc)
		 * @see org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean#getJarName()
		 */
		@XmlAttribute
		public String getJarName() {
			return jarName;
		}


		/* (non-Javadoc)
		 * @see org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean#setJarName(java.lang.String)
		 */
		public void setJarName(String jarName) {
			this.jarName = jarName;
		}
		
		/* (non-Javadoc)
		 * @see org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean#getModuleName()
		 */
		@XmlAttribute
		public String getModuleName() {
			return moduleName;
		}


		/* (non-Javadoc)
		 * @see org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean#setModuleName(java.lang.String)
		 */
		public void setModuleName(String moduleName) {
			this.moduleName = moduleName;
		}
		
		/* (non-Javadoc)
		 * @see org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean#getPart()
		 */
		@XmlAttribute
		public String getPart() {
			return part;
		}

		/* (non-Javadoc)
		 * @see org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean#setPart(java.lang.String)
		 */
		public void setPart(String part) {
			this.part = part;
		}


		/* (non-Javadoc)
		 * @see org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean#getResourceData()
		 */
		public byte[] getResourceData() {
			return resourceData;
		}


		/* (non-Javadoc)
		 * @see org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean#setResourceData(byte[])
		 */
		public void setResourceData(byte[] resourceData) {
			this.resourceData = resourceData;
		}


		/* (non-Javadoc)
		 * @see org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean#getTimeStamp()
		 */
		@XmlAttribute
		public long getTimeStamp() {
			return timeStamp;
		}


		/* (non-Javadoc)
		 * @see org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean#setTimeStamp(long)
		 */
		public void setTimeStamp(long timeStamp) {
			this.timeStamp = timeStamp;
		}


		/* (non-Javadoc)
		 * @see org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean#getDescription()
		 */
		public String getDescription() {
			return description;
		}


		/* (non-Javadoc)
		 * @see org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean#setDescription(java.lang.String)
		 */
		public void setDescription(String description) {
			this.description = description;
		}


		/* (non-Javadoc)
		 * @see org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean#getComment()
		 */
		public String getComment() {
			return comment;
		}


		/* (non-Javadoc)
		 * @see org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean#setComment(java.lang.String)
		 */
		public void setComment(String comment) {
			this.comment = comment;
		}
}
