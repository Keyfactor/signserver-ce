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

package org.signserver.cli.setdbtype;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * Utility that replaces the entity-mappings.xml file in a signserver.ear.
 * This is used to configure type database in a binary distribution of 
 * the SignServer.
 * 
 * The program takes two parameters:
 * path-to-signserver.ear
 * entitymappings-xml-path
 * 
 * @author Philip Vendil
 *
 */
public class SetDBType {
	
	private static final int SIGNSERVEREARPATH = 0;
	private static final int ENITYXMLPATH      = 1;

	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception {
		if(args.length != 2){
			displayUsageAndExit();			
		}
		
		File signServerEAR = new File(args[SIGNSERVEREARPATH]);
		if(!signServerEAR.exists() || !signServerEAR.canRead() || !signServerEAR.isFile()){
			System.out.println("Error reading signserver.ear, make sure the file " + args[SIGNSERVEREARPATH] + " is a file and readable for the user.");
			System.exit(-1);
		}
		
		File entityMappingXML = new File(args[ENITYXMLPATH]);
		if(!entityMappingXML.exists() || !entityMappingXML.canRead() || !entityMappingXML.isFile()){
			System.out.println("Error reading entity-mappings.xml, make sure the file " + args[ENITYXMLPATH] + " is a file and readable for the user.");
			System.exit(-1);
		}
		
		replaceEntityMappings(signServerEAR,entityMappingXML);
		

		// close the jar and ear again.
		
	}
	

	private static void replaceEntityMappings(File signserverearpath,File entityMappingXML) throws ZipException, IOException {
		ZipInputStream earFile = new ZipInputStream(new FileInputStream(signserverearpath));
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ZipOutputStream tempZip = new ZipOutputStream(baos);	
		ZipEntry next = earFile.getNextEntry();
		while(next != null){
			ByteArrayOutputStream  content = new ByteArrayOutputStream();
			byte[] data = new byte[30000];		  	
			int numberread;
			while(( numberread = earFile.read(data)) != -1){
				content.write(data,0,numberread);
			}
			if(next.getName().equals("signserver-ejb.jar")){
				content = replaceEntityMappings(content, entityMappingXML);
				next = new ZipEntry("signserver-ejb.jar");
			}

			tempZip.putNextEntry(next);
			tempZip.write(content.toByteArray());
			next = earFile.getNextEntry();

		}
		earFile.close();
		tempZip.close();
		
		FileOutputStream fos = new FileOutputStream(signserverearpath);
		fos.write(baos.toByteArray());
		fos.close();
	}


	private static ByteArrayOutputStream replaceEntityMappings(ByteArrayOutputStream content, File entityMappingXML) throws IOException {
		JarInputStream jarInputStream = new JarInputStream(new ByteArrayInputStream(content.toByteArray()));
		ByteArrayOutputStream retval = new ByteArrayOutputStream();
		JarOutputStream tempJar = new JarOutputStream(retval);
		
		HashSet<String> insertedNames = new HashSet<String>();
		
		JarEntry jarEntry = jarInputStream.getNextJarEntry();
		while(jarEntry != null){
			if(!insertedNames.contains(jarEntry.getName())){
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
                InputStream is = jarInputStream;
				if(jarEntry.getName().equals("META-INF/entity-mappings.xml")){					
					jarEntry = new JarEntry("META-INF/entity-mappings.xml");
					is = new FileInputStream(entityMappingXML);
				}
				byte[] data = new byte[30000];		  	
				int numberread;
				while(( numberread = is.read(data)) != -1){
					baos.write(data,0,numberread);
				}

				tempJar.putNextEntry(jarEntry);
				insertedNames.add(jarEntry.getName());
				tempJar.write(baos.toByteArray());
			}
			jarEntry = jarInputStream.getNextJarEntry();
		}
		
		tempJar.close();
		
		return retval;
	}


	private static void displayUsageAndExit() {
		System.out.println("Usage : java -jar setdbtype.jar <path-to-signserver.ear> <path-to-entity-mappings.xml>\n\n"+
				           "\n" +
				           "This program will replace the current entitymappings.xml with the given one" +
				           "to support multiple databases in binary releases.");
		System.exit(-1);
	}
	

}
