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

import java.io.DataInput;
import java.io.DataOutput;
import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

/**
 * Interface used in responses from the WorkerSession.process method. Should
 * be implemented by all types of workers.
 * 
 * 
 * @author Philip Vendil
 * $Id$
 */

public abstract class ProcessResponse implements Externalizable {
	

	   /**
	    * Method used to populate an empty IProcessRequest from a byte representation
	    * 
	    * The parse and serialize method are the methods that should be used
	    * by protocols to external clients. The Externalizable interface
	    * should only be used for RMI calls.
	    * 
	    * @param in input stream to read data from
	    * @throws IOException if parsing error occured
	    */
	    public abstract void parse(DataInput in) throws IOException;

	   /**
		* Method used to serialize a IProcess object
		* 
	    * The parse and serialize method are the methods that should be used
	    * by protocols to external clients. The Externalizable interface
	    * should only be used for RMI calls.
		* 
		* @param in input stream to read data from
		* @throws IOException if parsing error occured
		*/
	    public abstract void serialize(DataOutput out) throws IOException;

	    public void readExternal(ObjectInput in) throws IOException,
			ClassNotFoundException {    	
		    parse(in);
	    }

	    public void writeExternal(ObjectOutput out) throws IOException {
	       serialize(out);
	    }
}
