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
 
package org.signserver.common.clusterclassloader;

import java.io.IOException;
import java.io.PrintStream;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarInputStream;

import org.apache.log4j.Logger;

/**
 * Class loader used to find all classes that implements interfaces 
 * of a collection of classes. 
 * 
 * Should only be used temporary when uploading a plug-in zip
 * to the ClusterClassLoader.
 * 
 * @author Philip Vendil 15 maj 2008
 *
 */

public class FindInterfacesClassLoader extends ClassLoader {
	
	public transient Logger log = Logger.getLogger(this.getClass());
	
	/**
	 * HashMap containing class name of class and the actual class.
	 */
	private HashMap<String, byte[]> availableClasses = new HashMap<String,byte[]>();

	/**
	 * HashMap containing loaded classes by class name and Class
	 */
	HashMap<String, Class<?>> loadedClasses = new HashMap<String,Class<?>>();

	private PrintStream output;
	
	/**
	 * Constructor generating all classes in the MARFileParser
	 * So it is possible to search for implemented interfaces.
	 * @param MARFileParser to use as repository.
	 * @param part to generate classes for.
	 * @param output were warning, and error messages are sent.
	 * @throws IOException if something unexpected happened reading the Module Archive
	 */
	public FindInterfacesClassLoader(MARFileParser mARFileParser, String part, PrintStream output) throws IOException{
		this.output = output;
		
		Map<String, JarInputStream> jarFiles = mARFileParser.getJARFiles(part);
		for(String jarName : jarFiles.keySet()){
			Map<String, byte[]> resources = mARFileParser.getJarContent(jarFiles.get(jarName));
			for(String next : resources.keySet()){
				if(next.endsWith(".class")){
					availableClasses.put(ClusterClassLoaderUtils.getClassNameFromResourcePath(next), resources.get(next));
				}
			}
		}
		
		
	}
	
	/**
	 * Finds all implemented interfaces of the specified resource path.
	 * @param resourcePath with '/' and '.class'
	 * @return A List of implemented interfaces, an empty list if class couldn't be found or didn't implement any interfaces, never null
	 */
	public Collection<String> getImplementedInterfaces(String resourcePath){
		Set<String> implInterfaces = new HashSet<String>();
		Class<?> c = null;
		
		String classNameFromResourcePath = ClusterClassLoaderUtils.getClassNameFromResourcePath(resourcePath);
		try {		
			if(classNameFromResourcePath != null){
			  c = findClass(classNameFromResourcePath);
			}
		} catch (ClassNotFoundException e) {
			output.println("Error extracting interfaces, classes refered to by " + classNameFromResourcePath + " not found in CLI classpath.");
		} catch (NoClassDefFoundError e) {
			output.println("Error extracting interfaces, class refered to by " + classNameFromResourcePath + " not found in CLI classpath.");
		}

		
		if(c != null){
			for(Class<?> inter : c.getInterfaces()){
				implInterfaces.add(inter.getName());
			}
			if(c.getSuperclass() != null && !c.getSuperclass().getName().equals(Object.class.getName())){
			   String superClassResourceName = ClusterClassLoaderUtils.getResourcePathFromClassName(c.getSuperclass().getName());
               implInterfaces.addAll(getImplementedInterfaces(superClassResourceName));		
			}
		}
		
		return implInterfaces;
	}

	/* (non-Javadoc)
	 * @see java.lang.ClassLoader#findClass(java.lang.String)
	 */
	@Override
	protected Class<?> findClass(String name) throws ClassNotFoundException {
		byte[] classData = availableClasses.get(name);
		Class<?> retval = null;
		try{
			retval = getParent().loadClass(name);
		}catch(ClassNotFoundException e){			
			  if(loadedClasses.containsKey(name)){
				  retval = loadedClasses.get(name);
			  }else{
				  if(classData == null){
				    output.println("Warning : no class data found for resource with name : " + name + ".");
				  }else{
			         retval = defineClass(name, classData, 0, classData.length);
			         loadedClasses.put(name, retval);
				  }
			  }
		}
		
		if(retval == null){
			throw new ClassNotFoundException("Error class " + name + " not found.");
		}
		
		return retval;
	}
	

}
