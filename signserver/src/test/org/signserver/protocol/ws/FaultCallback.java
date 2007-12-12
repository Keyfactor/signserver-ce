package org.signserver.protocol.ws;

import org.signserver.protocol.ws.client.ICommunicationFault;
import org.signserver.protocol.ws.client.IFaultCallback;

public class FaultCallback implements IFaultCallback {
	boolean callBackCalled = false;
	
	public void addCommunicationError(ICommunicationFault fault) {
		//System.err.println("ERROR : " + fault.getDescription() + ": HOST : " + fault.getHostName() );
		
		if(fault.getThrowed()!= null){
			//System.err.print("StackTrace : " );
		  //fault.getThrowed().printStackTrace();
		}
		callBackCalled = true;
	}

	public boolean isCallBackCalled() {
		return callBackCalled;
	}

	
	
}
