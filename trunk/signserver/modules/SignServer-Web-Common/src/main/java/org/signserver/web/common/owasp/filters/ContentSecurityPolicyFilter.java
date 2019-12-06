/**
 *  Software published by the Open Web Application Security Project (http://www.owasp.org)
 *  https://www.owasp.org/index.php/Content_Security_Policy
 *
 */

package org.signserver.web.common.owasp.filters;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Hex;

/**
 * Sample filter implementation to define a set of Content Security Policies.<br>
 * 
 * This implementation has a dependency on Commons Codec API.<br>
 * 
 * This filter set CSP policies using all HTTP headers defined into W3C specification.<br>
 * <br>
 * This implementation is oriented to be easily understandable and easily adapted.<br>
 * 
 */
//@WebFilter("/*")
public class ContentSecurityPolicyFilter implements Filter {

	/** Configuration member to specify if web app use web fonts */
	public static final boolean APP_USE_WEBFONTS = true; // Used by /doc

	/** Configuration member to specify if web app use videos or audios */
	public static final boolean APP_USE_AUDIOS_OR_VIDEOS = false;

	/** Configuration member to specify if filter must add CSP directive used by Mozilla (Firefox) */
	public static final boolean INCLUDE_MOZILLA_CSP_DIRECTIVES = true;

	/** Filter configuration */
	@SuppressWarnings("unused")
	private FilterConfig filterConfig = null;

	/** List CSP HTTP Headers */
	private List<String> cspHeaders = new ArrayList<>();

	/** Collection of CSP polcies that will be applied */
	private String policies = null;

	/** Used for Script Nonce */
	private SecureRandom prng = null;

	/**
	 * Used to prepare (one time for all) set of CSP policies that will be applied on each HTTP response.
	 * 
	 * @see javax.servlet.Filter#init(javax.servlet.FilterConfig)
	 */
	@Override
	public void init(FilterConfig fConfig) throws ServletException {
		// Get filter configuration
		this.filterConfig = fConfig;

		// Init secure random
		try {
			this.prng = SecureRandom.getInstance("SHA1PRNG");
		}
		catch (NoSuchAlgorithmException e) {
			throw new ServletException(e);
		}

		// Define list of CSP HTTP Headers
		this.cspHeaders.add("Content-Security-Policy");
		this.cspHeaders.add("X-Content-Security-Policy");
		this.cspHeaders.add("X-WebKit-CSP");

		// Define CSP policies
		// Loading policies for Frame and Sandboxing will be dynamically defined : We need to know if context use Frame
		List<String> cspPolicies = new ArrayList<String>();
		String originLocationRef = "'self'";
		// --Disable default source in order to avoid browser fallback loading using 'default-src' locations
		//cspPolicies.add("default-src 'none'");
                cspPolicies.add("default-src " + "'self' blob:"); // 'self' and blob needed for /doc
		// --Define loading policies for Scripts
		cspPolicies.add("script-src " + originLocationRef + " 'unsafe-inline' 'unsafe-eval'");
		if (INCLUDE_MOZILLA_CSP_DIRECTIVES) {
			cspPolicies.add("options inline-script eval-script");
			cspPolicies.add("xhr-src 'self'");
		}
		// --Define loading policies for Plugins
		cspPolicies.add("object-src " + originLocationRef);
		// --Define loading policies for Styles (CSS)
		cspPolicies.add("style-src " + originLocationRef);
		// --Define loading policies for Images
		cspPolicies.add("img-src " + originLocationRef);
		// --Define loading policies for Form
		cspPolicies.add("form-action " + originLocationRef);
		// --Define loading policies for Audios/Videos
		if (APP_USE_AUDIOS_OR_VIDEOS) {
			cspPolicies.add("media-src " + originLocationRef);
		}
		// --Define loading policies for Fonts
		if (APP_USE_WEBFONTS) {
			cspPolicies.add("font-src " + originLocationRef);
		}
		// --Define loading policies for Connection
		cspPolicies.add("connect-src " + originLocationRef);
		// --Define loading policies for Plugins Types
		cspPolicies.add("plugin-types application/pdf application/x-shockwave-flash");
		// --Define browser XSS filtering feature running mode
		cspPolicies.add("reflected-xss block");

                // Uncomment to have violations posted by the browser
                //cspPolicies.add("report-uri http://localhost:8080/CSPReportURI-1.0-SNAPSHOT/ReceiveServlet");

		// Target formating
		this.policies = cspPolicies.toString().replaceAll("(\\[|\\])", "").replaceAll(",", ";").trim();
	}

	/**
	 * Add CSP policies on each HTTP response.
	 * 
	 * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain)
	 */
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain fchain) throws IOException, ServletException {
		HttpServletRequest httpRequest = ((HttpServletRequest) request);
		HttpServletResponse httpResponse = ((HttpServletResponse) response);

		/* Step 1 : Detect if target resource is a Frame */
		// Customize here according to your context...
		boolean isFrame = false;

		/* Step 2 : Add CSP policies to HTTP response */
		StringBuilder policiesBuffer = new StringBuilder(this.policies);

		// If resource is a frame add Frame/Sandbox CSP policy
		if (isFrame) {
			// Frame + Sandbox : Here sandbox allow nothing, customize sandbox options depending on your app....
			policiesBuffer.append(";").append("frame-src 'self';sandbox");
			if (INCLUDE_MOZILLA_CSP_DIRECTIVES) {
				policiesBuffer.append(";").append("frame-ancestors 'self'");
			}
		}

		// Add Script Nonce CSP Policy
		// --Generate a random number
		String randomNum = String.valueOf(this.prng.nextInt());
		// --Get its digest
		MessageDigest sha;
		try {
			sha = MessageDigest.getInstance("SHA-1");
		}
		catch (NoSuchAlgorithmException e) {
			throw new ServletException(e);
		}
		byte[] digest = sha.digest(randomNum.getBytes());
		// --Encode it into HEXA
		String scriptNonce = Hex.encodeHexString(digest);
		policiesBuffer.append(";").append("script-nonce ").append(scriptNonce);
		// --Made available script nonce in view app layer
		httpRequest.setAttribute("CSP_SCRIPT_NONCE", scriptNonce);

		// Add policies to all HTTP headers
		for (String header : this.cspHeaders) {
			httpResponse.setHeader(header, policiesBuffer.toString());
		}
                // Also add X-XSS-Protection, newer header. 
                // See https://www.owasp.org/index.php/List_of_useful_HTTP_headers
                // https://blogs.msdn.microsoft.com/ie/2008/07/02/ie8-security-part-iv-the-xss-filter/
                httpResponse.setHeader("X-XSS-Protection", "1; mode=block");
                // Also X-Content-Type-Options, see https://blogs.msdn.microsoft.com/ie/2008/09/02/ie8-security-part-vi-beta-2-update/
                httpResponse.setHeader("X-Content-Type-Options", "nosniff");

		/* Step 3 : Let request continue chain filter */
		fchain.doFilter(request, response);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @see javax.servlet.Filter#destroy()
	 */
	@Override
	public void destroy() {
		// Not used
	}
}