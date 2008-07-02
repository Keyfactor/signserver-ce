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
public class ClusterClassLoaderDataBean  {

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

  
    /**
     * Unique Id of the class, auto generated value
     *
     * @return unique Id and primary key
     */	
    public  int getId(){
    	return id;
    }

	/**
	 * @param id the id to set
	 */
	public void setId(int id) {
		this.id = id;
	}

	/**
	 * @return the resourceName (could be class name ) in path format.
	 * i.e a class called org.acme.AcmeWorker will have the path org/acme/AcmeWorker.class 
	 */
	public String getResourceName() {
		return resourceName;
	}


	/**
	 * @param resourceName  (could be class name ) in path format.
	 * i.e a class called org.acme.AcmeWorker will have the path org/acme/AcmeWorker.class
	 */
	public void setResourceName(String resourceName) {
		this.resourceName = resourceName;
	}


	/**
	 * @return the full interface names of all interfaces this
	 * class and all super classes is implementing, the String is
	 * ';' separated. Return "" if no interfaces is implemented.
	 */
	public String getImplInterfaces() {
		return implInterfaces;
	}


	/**
	 * @param implInterfaces the full interface names of all interfaces this
	 * class and all super classes is implementing, the String is
	 * ';' separated. Return "" if no interfaces is implemented.
	 */
	public void setImplInterfaces(String implInterfaces) {
		this.implInterfaces = implInterfaces;
	}


	/**
	 * @return version of the plug-in, should be one number for
	 * a classes in one zip. The greater number, the later version.
	 * If a Worker haven't got a version number defined in it's worker
	 * properties will the latest version be used.
	 */
	public int getVersion() {
		return version;
	}

	
	/**
	 * @return the type of file, i.e the postfix of the resource name in lower case without the '.'
	 * for example a classfile will have the name 'class' a someimage.jpg will have 'jpg'.
	 * 
	 */
	public String getType() {
		return type;
	}

	/**
	 * @param type of file, i.e the postfix of the resource name in lower case without the '.'
	 * for example a classfile will have the name 'class' a someimage.jpg will have 'jpg'.
	 */
	public void setType(String type) {
		this.type = type;
	}

	/**
	 * @param version  of the plug-in, should be one number for
	 * a classes in one zip. The greater number, the later version.
	 * If a Worker haven't got a version number defined in it's worker
	 * properties will the latest version be used.
	 */
	public void setVersion(int version) {
		this.version = version;
	}


	/**
	 * @return the name of the jar-file in the zip that 
	 * contained this class.
	 */
	public String getJarName() {
		return jarName;
	}


	/**
	 * @param jarName the name of the jar-file in the zip that 
	 * contained this class.
	 */
	public void setJarName(String jarName) {
		this.jarName = jarName;
	}
	
	/**
	 * @return the name of the MAR file  
	 * contained this class.
	 */
	public String getModuleName() {
		return moduleName;
	}


	/**
	 * @param moduleName the name of the MAR file that 
	 * contained this class.
	 */
	public void setModuleName(String moduleName) {
		this.moduleName = moduleName;
	}
	
	/**
	 * Returns all files specified in one part of the module archive
	 * 
	 * @return the part could be 'server' for server related resources
	 * or 'adminweb' for administrative web related resources or any
	 * other defined string supported by the rest of the system.
	 */
	public String getPart() {
		return part;
	}

	/**
	 * @param part could be 'server' for server related resources
	 * or 'adminweb' for administrative web related resources or any
	 * other defined string supported by the rest of the system.
	 */
	public void setPart(String part) {
		this.part = part;
	}


	/**
	 * @return the actual data of the resource, i.e class data
	 * or other file data.
	 */
	public byte[] getResourceData() {
		return resourceData;
	}


	/**
	 * @param resourceData the actual data of the resource, i.e class data
	 * or other file data.
	 */
	public void setResourceData(byte[] resourceData) {
		this.resourceData = resourceData;
	}


	/**
	 * @return the timeStamp when the zip was uploaded.
	 */
	public long getTimeStamp() {
		return timeStamp;
	}


	/**
	 * @param timeStamp when the zip was uploaded.
	 */
	public void setTimeStamp(long timeStamp) {
		this.timeStamp = timeStamp;
	}


	/**
	 * @return an optional description of the resource, reserved
	 * for future uses.
	 */
	public String getDescription() {
		return description;
	}


	/**
	 * @param description an optional description of the resource, reserved
	 * for future uses.
	 */
	public void setDescription(String description) {
		this.description = description;
	}


	/**
	 * @return an optional comment about the resource. Reserved
	 * for future use.
	 */
	public String getComment() {
		return comment;
	}


	/**
	 * @param comment an optional comment about the resource. Reserved
	 * for future use.
	 */
	public void setComment(String comment) {
		this.comment = comment;
	}


}
