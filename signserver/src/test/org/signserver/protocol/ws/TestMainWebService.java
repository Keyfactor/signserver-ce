package org.signserver.protocol.ws;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;

import javax.xml.namespace.QName;

import junit.framework.TestCase;

import org.signserver.protocol.ws.gen.InvalidWorkerIdException_Exception;
import org.signserver.protocol.ws.gen.SignServerWSService;
import org.signserver.protocol.ws.gen.WorkerStatusWS;

public class TestMainWebService extends TestCase {

	protected void setUp() throws Exception {
		super.setUp();
		
		
	}

	public void test1() throws MalformedURLException, InvalidWorkerIdException_Exception{
		
		QName qname = new QName("gen.ws.protocol.signserver.org", "SignServerWSService");
		SignServerWSService signServerWSService = new SignServerWSService(new URL("http://localhost:8080/signserver/signserverws/signserverws?wsdl"),qname);
		org.signserver.protocol.ws.gen.SignServerWS signServerWS =  signServerWSService.getSignServerWSPort();
		
		List<WorkerStatusWS> statuses = signServerWS.getStatus("1");
		assertTrue(statuses.size() == 1);
		
	}
}
