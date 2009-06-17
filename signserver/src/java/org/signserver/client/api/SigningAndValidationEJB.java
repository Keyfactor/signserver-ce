package org.signserver.client.api;

import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.GenericValidationRequest;
import org.signserver.common.GenericValidationResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.SignServerUtil;
import org.signserver.ejb.interfaces.IWorkerSession;

/**
 * Implements ISigningAndValidation using EJB remote interface.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class SigningAndValidationEJB implements ISigningAndValidation {

	private IWorkerSession.IRemote signserver;

	/**
	 * Creates an instance of SigningAndValidationEJB with default initial context:
	 * <pre>
	 * INITIAL_CONTEXT_FACTORY = "org.jnp.interfaces.NamingContextFactory"
	 * URL_PKG_PREFIXES = "org.jboss.naming:org.jnp.interfaces"
	 * PROVIDER_URL = "jnp://localhost:1099"
	 * </pre>
	 * 
	 * @throws NamingException If an naming exception is encountered.
	 */
	public SigningAndValidationEJB() throws NamingException {
		this(getInitialContext());
	}
	
	/**
	 * Creates an instance of SigningAndValidationEJB using the supplied context.
	 * 
	 * @param context Context to use for lookups.
	 * @throws NamingException If an naming exception is encountered.
	 */
	public SigningAndValidationEJB(Context context) throws NamingException {
		signserver = (IWorkerSession.IRemote) context.lookup(IWorkerSession.IRemote.JNDI_NAME);
		SignServerUtil.installBCProvider();
	}
	
	/**
	 * @return Default initial context.
	 * @throws NamingException If an naming exception is encountered.
	 */
	private static Context getInitialContext() throws NamingException {
		Hashtable<String, String> props = new Hashtable<String, String>();
		props.put(Context.INITIAL_CONTEXT_FACTORY, "org.jnp.interfaces.NamingContextFactory");
		props.put(Context.URL_PKG_PREFIXES, "org.jboss.naming:org.jnp.interfaces");
		props.put(Context.PROVIDER_URL, "jnp://localhost:1099");
		Context ctx = new InitialContext(props);
		return ctx;
	}

	public GenericSignResponse sign(String signerIdOrName, byte[] xmlDocument) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
		GenericSignRequest request = new GenericSignRequest(1, xmlDocument);
		ProcessResponse resp = process(getWorkerId(signerIdOrName), request, new RequestContext());
		if(!(resp instanceof GenericSignResponse)) {
			throw new SignServerException("Unexpected response type: " + resp.getClass().getName());
		}
		return (GenericSignResponse) resp; 
	}

	public GenericValidationResponse validate(String validatorIdOrName, byte[] xmlDocument) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
		ProcessResponse resp = process(getWorkerId(validatorIdOrName), new GenericValidationRequest(1, xmlDocument), new RequestContext());
		if(!(resp instanceof GenericValidationResponse)) {
			throw new SignServerException("Unexpected response type: " + resp.getClass().getName());
		}
		return (GenericValidationResponse) resp;
	}

	private int getWorkerId(String workerIdOrName) throws IllegalRequestException{
    	int retval = 0;
    	
    	if(workerIdOrName.substring(0, 1).matches("\\d")) {
    		retval = Integer.parseInt(workerIdOrName);    		
    	} else {
    		retval = signserver.getWorkerId(workerIdOrName);
    		if(retval == 0) {
    			throw new IllegalRequestException("Error: No worker with the given name could be found");
    		}
    	}
    	return retval;
    }
	
	public ProcessResponse process(int workerId, ProcessRequest request, RequestContext context) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
		return signserver.process(workerId, request, context);
	}
	
}
