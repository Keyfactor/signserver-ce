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

 
package org.signserver.common;

import org.ejbca.core.model.UpgradeableDataHashMap;


/**
 * Class containing the actual archive data.
 * Is responsible for containing the archive data as
 * byre array.
 * 
 * 
 * @author Philip Vendil
 * $Id$
 */
public class ArchiveData extends UpgradeableDataHashMap {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private static final float LATEST_VERSION = 1;
	
	private static final String ARCHIVEDATA ="ARCHIVEDATA";

	/**
	 * Don't use this constructor, should only be used internally
	 *
	 */
	public ArchiveData(){}
	
	/**
	 * Constructor that should be used to create an archive data.
	 * @param archiveData
	 */
	@SuppressWarnings("unchecked")
	public ArchiveData(byte[] archiveData){
       data.put(ARCHIVEDATA,archiveData);
	}
	

	public byte[] getData(){
		return (byte[]) data.get(ARCHIVEDATA);
	}



	public float getLatestVersion() {		
		return LATEST_VERSION;
	}

	public void upgrade() {
		
		
	}



}
