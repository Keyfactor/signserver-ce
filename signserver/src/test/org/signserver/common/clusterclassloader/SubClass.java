package org.signserver.common.clusterclassloader;

import javax.jws.WebParam;

import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.module.wsra.common.AuthorizationDeniedException;
import org.signserver.server.annotations.Transaction;

public class SubClass extends BaseClass implements FooInterface{

	public boolean haveRun = false;
	
	@Transaction
	public void revokeToken(@WebParam(name="tokenSerialNumber")String tokenSerialNumber, @WebParam(name="revocationReason")int reason) throws IllegalRequestException, SignServerException, AuthorizationDeniedException{
	
		if(tokenSerialNumber.equals("exception")){
			throw new IllegalRequestException("Test");
			
		}
		haveRun = true;		
		return;
	}

	@Override
	public boolean hasRun() {
		return haveRun;
	}

	/*
	public void foo(String arg) throws IOException {
		if(arg.equals("exception")){
			throw new IOException("Test");
			
		}
		haveRun = true;		
		return;
		
	}*/
}
