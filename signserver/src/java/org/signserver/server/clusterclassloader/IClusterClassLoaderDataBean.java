package org.signserver.server.clusterclassloader;

/**
 * Interface containing all methods accessible for the actual data object of the different persistence 
 * implementations of the Cluster Class Loader.
 *           
 * @author Philip Vendil
 */
public interface IClusterClassLoaderDataBean {

	/**
	 * Unique Id of the class, auto generated value
	 *
	 * @return unique Id and primary key
	 */
	int getId();

	/**
	 * @param id the id to set
	 */
	void setId(int id);

	/**
	 * @return the resourceName (could be class name ) in path format.
	 * i.e a class called org.acme.AcmeWorker will have the path org/acme/AcmeWorker.class 
	 */
	String getResourceName();

	/**
	 * @param resourceName  (could be class name ) in path format.
	 * i.e a class called org.acme.AcmeWorker will have the path org/acme/AcmeWorker.class
	 */
	void setResourceName(String resourceName);

	/**
	 * @return the full interface names of all interfaces this
	 * class and all super classes is implementing, the String is
	 * ';' separated. Return "" if no interfaces is implemented.
	 */
	String getImplInterfaces();

	/**
	 * @param implInterfaces the full interface names of all interfaces this
	 * class and all super classes is implementing, the String is
	 * ';' separated. Return "" if no interfaces is implemented.
	 */
	void setImplInterfaces(String implInterfaces);

	/**
	 * @return version of the plug-in, should be one number for
	 * a classes in one zip. The greater number, the later version.
	 * If a Worker haven't got a version number defined in it's worker
	 * properties will the latest version be used.
	 */
	int getVersion();

	/**
	 * @return the type of file, i.e the postfix of the resource name in lower case without the '.'
	 * for example a classfile will have the name 'class' a someimage.jpg will have 'jpg'.
	 * 
	 */
	String getType();

	/**
	 * @param type of file, i.e the postfix of the resource name in lower case without the '.'
	 * for example a classfile will have the name 'class' a someimage.jpg will have 'jpg'.
	 */
	void setType(String type);

	/**
	 * @param version  of the plug-in, should be one number for
	 * a classes in one zip. The greater number, the later version.
	 * If a Worker haven't got a version number defined in it's worker
	 * properties will the latest version be used.
	 */
	void setVersion(int version);

	/**
	 * @return the name of the jar-file in the zip that 
	 * contained this class.
	 */
	String getJarName();

	/**
	 * @param jarName the name of the jar-file in the zip that 
	 * contained this class.
	 */
	void setJarName(String jarName);

	/**
	 * @return the name of the MAR file  
	 * contained this class.
	 */
	String getModuleName();

	/**
	 * @param moduleName the name of the MAR file that 
	 * contained this class.
	 */
	void setModuleName(String moduleName);

	/**
	 * Returns all files specified in one part of the module archive
	 * 
	 * @return the part could be 'server' for server related resources
	 * or 'adminweb' for administrative web related resources or any
	 * other defined string supported by the rest of the system.
	 */
	String getPart();

	/**
	 * @param part could be 'server' for server related resources
	 * or 'adminweb' for administrative web related resources or any
	 * other defined string supported by the rest of the system.
	 */
	void setPart(String part);

	/**
	 * @return the actual data of the resource, i.e class data
	 * or other file data.
	 */
	byte[] getResourceData();

	/**
	 * @param resourceData the actual data of the resource, i.e class data
	 * or other file data.
	 */
	void setResourceData(byte[] resourceData);

	/**
	 * @return the timeStamp when the zip was uploaded.
	 */
	long getTimeStamp();

	/**
	 * @param timeStamp when the zip was uploaded.
	 */
	void setTimeStamp(long timeStamp);

	/**
	 * @return an optional description of the resource, reserved
	 * for future uses.
	 */
	String getDescription();

	/**
	 * @param description an optional description of the resource, reserved
	 * for future uses.
	 */
	void setDescription(String description);

	/**
	 * @return an optional comment about the resource. Reserved
	 * for future use.
	 */
	String getComment();

	/**
	 * @param comment an optional comment about the resource. Reserved
	 * for future use.
	 */
	void setComment(String comment);

}