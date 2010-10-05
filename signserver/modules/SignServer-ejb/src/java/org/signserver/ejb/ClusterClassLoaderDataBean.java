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
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;

import org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean;




/**
 * Entity Bean used as a back-end for the ClusterClassLoader
 * to have a centralized class repository for all nodes in
 * a SignServer cluster. It's can have multiple versions of
 * one plug-in within a same cluster.
 * 
 * Information stored:
 * <pre>
 * id                        : (PrimaryKey, int) (Not Null)
 * resourceName              : String (Not Null)  
 * implInterfaces            : String 
 * version                   : int (Not Null) 
 * type                      : String (Not Null)
 * jarName                   : String (Not Null)                  
 * moduleName                : String (Not Null) 
 * part                      : String (Not Null)  
 * resourceData              : String (Not Null) 
 * timeStamp                 : long (Not Null) 
 * description               : String
 * comment                   : String 
 * </pre>
 *
 * @author Philip Vendil
 *
 */
@Entity
@Table(name="ClusterClassLoaderData")
@NamedQueries(
		{@NamedQuery(name="ClusterClassLoaderDataBean.findByResourceName",query="SELECT a from ClusterClassLoaderDataBean a WHERE a.resourceName=?1 AND a.moduleName = ?2 AND a.part = ?3 AND a.version = ?4"),
		 @NamedQuery(name="ClusterClassLoaderDataBean.findLatestVersionOfResource",query="SELECT max(a.version) from ClusterClassLoaderDataBean a WHERE a.resourceName=?1"),
		 @NamedQuery(name="ClusterClassLoaderDataBean.findLatestVersionOfModule",query="SELECT max(a.version) from ClusterClassLoaderDataBean a WHERE a.moduleName=?1"),		 
		 @NamedQuery(name="ClusterClassLoaderDataBean.findResources",query="SELECT a from ClusterClassLoaderDataBean a WHERE a.moduleName=?1 AND a.part=?2 AND a.version=?3"),
		 @NamedQuery(name="ClusterClassLoaderDataBean.findAllResourcesInModule",query="SELECT a from ClusterClassLoaderDataBean a WHERE a.moduleName=?1 AND a.version=?2"),
		 @NamedQuery(name="ClusterClassLoaderDataBean.findAllModules",query="SELECT distinct a.moduleName from ClusterClassLoaderDataBean a "),
		 @NamedQuery(name="ClusterClassLoaderDataBean.findAllVersionOfModule",query="SELECT distinct a.version from ClusterClassLoaderDataBean a WHERE a.moduleName = ?1"),
		 @NamedQuery(name="ClusterClassLoaderDataBean.findAllPartsOfModule",query="SELECT distinct a.part from ClusterClassLoaderDataBean a WHERE a.moduleName = ?1 and a.version = ?2"),
		 @NamedQuery(name="ClusterClassLoaderDataBean.findAllJarsInPart",query="SELECT distinct a.jarName from ClusterClassLoaderDataBean a WHERE a.moduleName = ?1 AND a.part = ?2 AND a.version = ?3"),
		 @NamedQuery(name="ClusterClassLoaderDataBean.findAllResourcesInJar",query="SELECT a from ClusterClassLoaderDataBean a WHERE a.moduleName = ?1 AND a.part = ?2 AND a.version = ?3 AND a.jarName=?4"),
		 @NamedQuery(name="ClusterClassLoaderDataBean.findImplementorsInModule",query="SELECT a from ClusterClassLoaderDataBean a WHERE a.implInterfaces LIKE ?1 AND a.moduleName=?2 AND a.part=?3")
		})
public class ClusterClassLoaderDataBean implements IClusterClassLoaderDataBean  {

   @Id
   @GeneratedValue
   @Column(nullable=false)
   private int id;
   @Column(nullable=false)
   private String resourceName;
   @Column(length=64000,nullable=false)
   private String implInterfaces;
   @Column(nullable=false)
   private int version;    
   @Column(nullable=false)
   private String type;
   @Column(nullable=false)
   private String jarName;
   @Column(nullable=false)
   private String moduleName;
   @Column(nullable=false)
   private String part;
   @Lob
   @Column(length=10485760,nullable=false)
   private byte[] resourceData;
   @Column(nullable=false)
   private long timeStamp;
   @Column(length=64000)
   private String description;
   @Column(length=64000)
   private String comment;

  
    /* (non-Javadoc)
	 * @see org.signserver.ejb.IClusterClassLoaderDataBean#getId()
	 */	
    public  int getId(){
    	return id;
    }

	/* (non-Javadoc)
	 * @see org.signserver.ejb.IClusterClassLoaderDataBean#setId(int)
	 */
	public void setId(int id) {
		this.id = id;
	}

	/* (non-Javadoc)
	 * @see org.signserver.ejb.IClusterClassLoaderDataBean#getResourceName()
	 */
	public String getResourceName() {
		return resourceName;
	}


	/* (non-Javadoc)
	 * @see org.signserver.ejb.IClusterClassLoaderDataBean#setResourceName(java.lang.String)
	 */
	public void setResourceName(String resourceName) {
		this.resourceName = resourceName;
	}


	/* (non-Javadoc)
	 * @see org.signserver.ejb.IClusterClassLoaderDataBean#getImplInterfaces()
	 */
	public String getImplInterfaces() {
		return implInterfaces;
	}


	/* (non-Javadoc)
	 * @see org.signserver.ejb.IClusterClassLoaderDataBean#setImplInterfaces(java.lang.String)
	 */
	public void setImplInterfaces(String implInterfaces) {
		this.implInterfaces = implInterfaces;
	}


	/* (non-Javadoc)
	 * @see org.signserver.ejb.IClusterClassLoaderDataBean#getVersion()
	 */
	public int getVersion() {
		return version;
	}

	
	/* (non-Javadoc)
	 * @see org.signserver.ejb.IClusterClassLoaderDataBean#getType()
	 */
	public String getType() {
		return type;
	}

	/* (non-Javadoc)
	 * @see org.signserver.ejb.IClusterClassLoaderDataBean#setType(java.lang.String)
	 */
	public void setType(String type) {
		this.type = type;
	}

	/* (non-Javadoc)
	 * @see org.signserver.ejb.IClusterClassLoaderDataBean#setVersion(int)
	 */
	public void setVersion(int version) {
		this.version = version;
	}


	/* (non-Javadoc)
	 * @see org.signserver.ejb.IClusterClassLoaderDataBean#getJarName()
	 */
	public String getJarName() {
		return jarName;
	}


	/* (non-Javadoc)
	 * @see org.signserver.ejb.IClusterClassLoaderDataBean#setJarName(java.lang.String)
	 */
	public void setJarName(String jarName) {
		this.jarName = jarName;
	}
	
	/* (non-Javadoc)
	 * @see org.signserver.ejb.IClusterClassLoaderDataBean#getModuleName()
	 */
	public String getModuleName() {
		return moduleName;
	}


	/* (non-Javadoc)
	 * @see org.signserver.ejb.IClusterClassLoaderDataBean#setModuleName(java.lang.String)
	 */
	public void setModuleName(String moduleName) {
		this.moduleName = moduleName;
	}
	
	/* (non-Javadoc)
	 * @see org.signserver.ejb.IClusterClassLoaderDataBean#getPart()
	 */
	public String getPart() {
		return part;
	}

	/* (non-Javadoc)
	 * @see org.signserver.ejb.IClusterClassLoaderDataBean#setPart(java.lang.String)
	 */
	public void setPart(String part) {
		this.part = part;
	}


	/* (non-Javadoc)
	 * @see org.signserver.ejb.IClusterClassLoaderDataBean#getResourceData()
	 */
	public byte[] getResourceData() {
		return resourceData;
	}


	/* (non-Javadoc)
	 * @see org.signserver.ejb.IClusterClassLoaderDataBean#setResourceData(byte[])
	 */
	public void setResourceData(byte[] resourceData) {
		this.resourceData = resourceData;
	}


	/* (non-Javadoc)
	 * @see org.signserver.ejb.IClusterClassLoaderDataBean#getTimeStamp()
	 */
	public long getTimeStamp() {
		return timeStamp;
	}


	/* (non-Javadoc)
	 * @see org.signserver.ejb.IClusterClassLoaderDataBean#setTimeStamp(long)
	 */
	public void setTimeStamp(long timeStamp) {
		this.timeStamp = timeStamp;
	}


	/* (non-Javadoc)
	 * @see org.signserver.ejb.IClusterClassLoaderDataBean#getDescription()
	 */
	public String getDescription() {
		return description;
	}


	/* (non-Javadoc)
	 * @see org.signserver.ejb.IClusterClassLoaderDataBean#setDescription(java.lang.String)
	 */
	public void setDescription(String description) {
		this.description = description;
	}


	/* (non-Javadoc)
	 * @see org.signserver.ejb.IClusterClassLoaderDataBean#getComment()
	 */
	public String getComment() {
		return comment;
	}


	/* (non-Javadoc)
	 * @see org.signserver.ejb.IClusterClassLoaderDataBean#setComment(java.lang.String)
	 */
	public void setComment(String comment) {
		this.comment = comment;
	}


}
