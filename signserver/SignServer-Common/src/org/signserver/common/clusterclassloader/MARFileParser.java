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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Class in charge of extracting information from a Module Archive.
 * 
 * 
 * @author Philip Vendil 15 maj 2008
 *
 */

public class MARFileParser {

	public static final String MARDESCRIPTOR_PATH = "META-INF/mar-descriptor.properties";
	
	public static final String MARDESCRIPTOR_VERSION = "version";
	public static final String MARDESCRIPTOR_DEFAULTDESCRIPTION = "default-description";
	
	public static final String MARDESCRIPTOR_MODULENAME = "modulename";
	
	
	private static final String NAME_PARTCONFIGPROPERTIES = "part-config.properties";
	
	public static final String MARDESCRIPTOR_PARTS = "parts";
	private static final String[] DEFAULT_PARTS = {"server"};
	
	private HashMap<String, byte[]> mARContent = new HashMap<String, byte[]>();
	
	private Properties mARDescriptor = new Properties(); 	
	private String[] parts = DEFAULT_PARTS;	
	private String marName;
	
	public MARFileParser(String parFilePath) throws IOException, IllegalMARFileException{
		this(new File(parFilePath));
	}
	
	public MARFileParser(File pARFile) throws IOException, IllegalMARFileException{
		if(!pARFile.exists()){
			throw new IOException("Error parsing MAR file, File " + pARFile.getName() + " doesn't seem to exists.");
		}
		if(pARFile.isDirectory()){
			throw new IOException("Error parsing MAR file, File " + pARFile.getName() + " is a directory and not a file.");
		}
		if(!pARFile.canRead()){
			throw new IOException("Error parsing MAR file " + pARFile.getName() + ", no read access.");
		}
		
		ZipInputStream zipInputStream = new ZipInputStream(new FileInputStream(pARFile));
		ZipEntry zipEntry = zipInputStream.getNextEntry();
		while(zipEntry != null){
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			int b = -1;
			while((b = zipInputStream.read()) != -1){
				baos.write(b);
			}
			mARContent.put(zipEntry.getName(), baos.toByteArray());	
			zipInputStream.closeEntry();
			zipEntry = zipInputStream.getNextEntry();
		}
		
		mARDescriptor = new Properties();
		if(mARContent.get(MARDESCRIPTOR_PATH) != null){
			mARDescriptor.load(new ByteArrayInputStream((byte[]) mARContent.get(MARDESCRIPTOR_PATH)));			
		}
		
		try{
			getVersionFromMARFile();
		}catch(NumberFormatException e){
			throw new IllegalMARFileException("Error parsing MAR file, the field " + MARDESCRIPTOR_VERSION + " should have an integer value instead of" + mARDescriptor.getProperty(MARDESCRIPTOR_VERSION));
		}
		
		String partsTemp = mARDescriptor.getProperty(MARDESCRIPTOR_PARTS);
		if(partsTemp != null){
			parts = partsTemp.split(",");
			for(int i=0;i<parts.length;i++){
				parts[i] = parts[i].trim();
			}			
		}
		

						
	    marName = pARFile.getName();	
	}
			
	/**
	 * @return The name of the Module Archive without path.
	 */
	public String getMARName(){
		return marName;
	}
	
	/**
	 * Returns the module name which is the 'name' field in the descriptor, if the field doesn't exists in
	 * the descriptor will the filename in upper case without the .MAR extension be used.
	 * @return The name of the Module 
	 */
	public String getModuleName(){
		String retval = getMARDescriptor().getProperty(MARDESCRIPTOR_MODULENAME);
		if(retval == null){
			retval = getMARName().toUpperCase();
			if(retval.endsWith(".MAR")){
				retval = retval.substring(0,retval.length()-4);
			}
		}else{
			retval = retval.toUpperCase();
		}
		
		return retval;
	}
	
	/**
	 * Method parsing a module Archive for the version number in
	 * of the descriptor.
	 * 
	 * @return version number or 1 if no version could be found.
	 */
	public int getVersionFromMARFile(){
		int retval = 1;
		if(mARDescriptor.get(MARDESCRIPTOR_VERSION) != null){
			retval = Integer.parseInt(mARDescriptor.getProperty(MARDESCRIPTOR_VERSION));
		}
		return retval;
	}
	
	/**
	 * Method parsing a Module Archive for the description in
	 * of the descriptor.
	 * 
	 * @return the descripton in mar file or an empty string if it
	 * couldn't be found.
	 */
	public String getDescriptionFromMARFile(){
		String retval = "";
		if(mARDescriptor.getProperty(MARDESCRIPTOR_DEFAULTDESCRIPTION) != null){
			retval = mARDescriptor.getProperty(MARDESCRIPTOR_DEFAULTDESCRIPTION);
		}
		return retval.trim();
	}
	
	/**
	 * 
	 * @return the properties defined in the MAR descriptor or an
	 * empty Properties if no such file was found.
	 */
	public Properties getMARDescriptor(){
		return mARDescriptor;		
	}
	
	
	/**
	 * @return Returns an array of all configured parts in
	 * this MAR file.
	 */
	public String[] getMARParts(){
		return parts;
	}

	/**
	 * Method that returns all Jar files in a part of the 
	 * module.
	 * @param part one of the defined modules.
	 * @return a Map with jarName and data
	 * @throws IOException if error occurred when reading the Jar files
	 */
	public Map<String, JarInputStream> getJARFiles(String part) throws IOException{
		Map<String, JarInputStream> retval  = new HashMap<String, JarInputStream>();
		for(String resourcePath : mARContent.keySet()){
			if(resourcePath.startsWith(part)){
				if(resourcePath.endsWith(".jar")){
					JarInputStream jis = new JarInputStream(new ByteArrayInputStream(mARContent.get(resourcePath)));					
					retval.put(ClusterClassLoaderUtils.removePath(resourcePath),jis);
				}
			}
		}
		
		return retval;
	}
	
	/**
	 * Method used to get all files in the Jar with paths and content.
	 * @param jarInputStream the Jar to parse
	 * @return a HashMap with path and file content.
	 * @throws IOException if unexpected error occurred during JarFile Parsing.
	 */
	public HashMap<String,byte[]> getJarContent(JarInputStream jarInputStream) throws IOException{
		HashMap<String,byte[]> retval = new HashMap<String,byte[]>();
		
		JarEntry jarEntry = jarInputStream.getNextJarEntry();
		while(jarEntry != null){
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			int b = -1;
			while((b = jarInputStream.read()) != -1){
				baos.write(b);
			}
			retval.put(jarEntry.getName(), baos.toByteArray());	
			jarInputStream.closeEntry();
			jarEntry = jarInputStream.getNextJarEntry();
		}
		
		return retval;
	}
	
	/**
	 * Method that returns the part configuration of the specified part and environment
	 * 
	 * The part configuration should lie in the path: <part>/<environment>-part-config.properties
	 * if the specified file doesn't exists is <part>/part-config.properties fetched
	 * 
	 * @param part the module part to look in.
	 * @param environement should be a lowercase string containing the environment
	 *  the module should be installed in, could be 'devel', 'test' or 'prod' but also
	 *  a user defined value. Use null if the environment option shouldn't be used.
	 * @return the configuration or null if no path configuration existed.
	 * @throws IOException if unexpected error occurred during retrieval of part configuration
	 */
	public Properties getPartConfig(String part, String environment) throws IOException{
		Properties retval = null;
		byte[] content = null;
		if(environment != null){
			content = mARContent.get(part  + "/" + environment.toLowerCase() + "-" + NAME_PARTCONFIGPROPERTIES);
		}
		if(content == null){
			content = mARContent.get(part  + "/" + NAME_PARTCONFIGPROPERTIES);
		}
		if(content != null){
			ByteArrayInputStream bais = new ByteArrayInputStream(content);
			retval = new Properties();
			retval.load(bais);
		}
	  return retval;
	}
}
