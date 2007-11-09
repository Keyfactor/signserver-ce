package org.signserver.common;


/**
 * Interface used for requests to WorkerSession.process method. Should
 * be implemented by all types of signers.
 * 
 * 
 * @author Philip Vendil
 * $Id: ISignRequest.java,v 1.2 2007-11-09 15:45:49 herrvendil Exp $
 */
public interface ISignRequest extends IProcessRequest {

	/**
	 * Should contain a unique request id used to identify the request
	 */
    public int getRequestID();

    
    /**
     * Should contain the data that should be signed.
     */
    public Object getRequestData();
	
}
