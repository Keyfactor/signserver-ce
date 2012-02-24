package org.signserver.web;

import java.util.HashMap;
import java.util.Map;

public class GenericProcessServletWorkerResponseTest extends WebTestCase {

	private final static String UNEXISTING_WORKER_NAME = "_NotExistingWorker123_";
	private final static int UNEXISTING_WORKER_ID = 4711;
	
	private String currentWorkerName = null;
	
	@Override
	protected String getServletURL() {
		return "http://localhost:8080/signserver/worker/" + currentWorkerName;
	}

	@Override
	protected void setUp() throws Exception {
		addDummySigner1();
		currentWorkerName = this.getSignerNameDummy1();
	}

	@Override
	protected void tearDown() throws Exception {
		removeWorker(getSignerIdDummy1());
	}
    
	/**
	 * Test correct request with the worker addressed in the URL
	 */
	public void test01HttpStatus200() {
		Map<String, String> fields = new HashMap<String, String>();
		fields.put("data", "<root/>");
		
		assertStatusReturned(fields, 200);
	}
	
	/**
	 * Test correct request, overriding an unexisting worker name set by a request
	 * parameter
	 */
	public void test02HttpStatus200_overrideRequestParamWorkerName() {
		Map<String, String> fields = new HashMap<String, String>();
		fields.put("data", "<root/>");
		fields.put("workerName", UNEXISTING_WORKER_NAME);
		
		assertStatusReturned(fields, 200);
	}
	
	/**
	 * Test correct request, overriding an unexisting worker ID set by a request
	 * parameter.
	 */
	public void test03HttpStatus200_overrideRequestParamWorkerId() {
		Map<String, String> fields = new HashMap<String, String>();
		fields.put("data", "<root/>");
		fields.put("workerId", String.valueOf(UNEXISTING_WORKER_ID));
		
		assertStatusReturned(fields, 200);
	}
	
	/**
	 * Test with incorrect worker name in the URL.
	 */
	public void test04HttpStatus404() {
		currentWorkerName = UNEXISTING_WORKER_NAME;
		Map<String, String> fields = new HashMap<String, String>();
		fields.put("data", "<root/>");
		
		assertStatusReturned(fields, 404);
	}
	
	/**
	 * Test with incorrect worker name in the URL.
	 * Set an existing worker name using request parameter.
	 * The name used in the URL should override the request parameter and result
	 * in a 404.
	 */
	public void test05HttpStatus404_setCorrectWorkerNameRequestParam() {
		currentWorkerName = UNEXISTING_WORKER_NAME;
		Map<String, String> fields = new HashMap<String, String>();
		fields.put("data", "<root/>");
		fields.put("workerName", getSignerNameDummy1());
		
		assertStatusReturned(fields, 404);
	}
	
	/**
	 * Test with incorrect worker name in the URL.
	 * Set an existing worker ID using request parameter.
	 * The name used in the URL should override the request parameter and result
	 * in a 404.
	 */
	public void test06HttpStatus404_setCorrectWorkerIdRequestParam() {
		currentWorkerName = UNEXISTING_WORKER_NAME;
		Map<String, String> fields = new HashMap<String, String>();
		fields.put("data", "<root/>");
		fields.put("workerId", String.valueOf(getSignerIdDummy1()));
		
		assertStatusReturned(fields, 404);
	}
	
	/**
	 * Test with incorrect worker name in the URL.
	 * Set an existing worker name and ID using request parameter.
	 * The name used in the URL should override the request parameter and result
	 * in a 404.
	 */
	public void test07HttpStatus404_setCorrectWorkerIdAndNameRequestParam() {
		currentWorkerName = UNEXISTING_WORKER_NAME;
		Map<String, String> fields = new HashMap<String, String>();
		fields.put("data", "<root/>");
		fields.put("workerId", String.valueOf(getSignerIdDummy1()));
		fields.put("workerName", getSignerNameDummy1());
		
		assertStatusReturned(fields, 404);
	}
}
