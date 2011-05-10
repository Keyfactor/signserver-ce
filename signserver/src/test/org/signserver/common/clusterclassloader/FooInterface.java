package org.signserver.common.clusterclassloader;

import javax.jws.WebParam;

import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.module.wsra.common.AuthorizationDeniedException;

public interface FooInterface{
	//void foo(String arg) throws IOException;
	public void revokeToken(@WebParam(name="tokenSerialNumber")String tokenSerialNumber, @WebParam(name="revocationReason")int reason) throws IllegalRequestException, SignServerException, AuthorizationDeniedException;
	boolean hasRun();
}
