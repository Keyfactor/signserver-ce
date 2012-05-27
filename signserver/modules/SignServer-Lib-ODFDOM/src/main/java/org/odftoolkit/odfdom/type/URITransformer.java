/************************************************************************
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER
 * 
 * Copyright 2008 Sun Microsystems, Inc. All rights reserved.
 * 
 * Use is subject to license terms.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0. You can also
 * obtain a copy of the License at http://odftoolkit.org/docs/license.txt
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * 
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ************************************************************************/
package org.odftoolkit.odfdom.type;

import java.io.UnsupportedEncodingException;
import java.util.BitSet;
import java.io.ByteArrayOutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Transformations for transporting URIs in URLs.
 *
 * <h4> URIs, URLs, and URNs </h4>
 *
 * A URI is a uniform resource <i>identifier</i> while a URL is a uniform
 * resource <i>locator</i>.  Hence every URL is a URI, abstractly speaking, but
 * not every URI is a URL.  This is because there is another subcategory of
 * URIs, uniform resource <i>names</i> (URNs), which name resources but do not
 * specify how to locate them.  The <tt>mailto</tt>, <tt>news</tt>, and
 * <tt>isbn</tt> URIs shown above are examples of URNs.
 *
 *
 * <h4>URI syntax and components</h4>
 *
 * At the highest level a URI reference (hereinafter simply "URI") in string
 * form has the syntax
 *
 * <blockquote>
 * [<i>scheme</i><tt><b>:</b></tt><i></i>]<i>scheme-specific-part</i>[<tt><b>#</b></tt><i>fragment</i>]
 * </blockquote>
 *
 * where square brackets [...] delineate optional components and the characters
 * <tt><b>:</b></tt> and <tt><b>#</b></tt> stand for themselves.
 *
 * <p> An <i>absolute</i> URI specifies a scheme; a URI that is not absolute is
 * said to be <i>relative</i>.  URIs are also classified according to whether
 * they are <i>opaque</i> or <i>hierarchical</i>.
 *
 * <p> An <i>opaque</i> URI is an absolute URI whose scheme-specific part does
 * not begin with a slash character (<tt>'/'</tt>).  Opaque URIs are not
 * subject to further parsing.  Some examples of opaque URIs are:
 *
 * <blockquote><table cellpadding=0 cellspacing=0>
 * <tr><td><tt>mailto:java-net@java.sun.com</tt><td></tr>
 * <tr><td><tt>news:comp.lang.java</tt><td></tr>
 * <tr><td><tt>urn:isbn:096139210x</td></tr>
 * </table></blockquote>
 *
 * <p> A <i>hierarchical</i> URI is either an absolute URI whose
 * scheme-specific part begins with a slash character, or a relative URI, that
 * is, a URI that does not specify a scheme.  Some examples of hierarchical
 * URIs are:
 *
 * <blockquote>
 * <tt>http://java.sun.com/j2se/1.3/</tt><br>
 * <tt>docs/guide/collections/designfaq.html#28</tt></br>
 * <tt>../../../demo/jfc/SwingSet2/src/SwingSet2.java</tt></br>
 * <tt>file:///~/calendar</tt>
 * </blockquote>
 *
 * <p> A hierarchical URI is subject to further parsing according to the syntax
 *
 * <blockquote>
 * [<i>scheme</i><tt><b>:</b></tt>][<tt><b>//</b></tt><i>authority</i>][<i>path</i>][<tt><b>?</b></tt><i>query</i>][<tt><b>#</b></tt><i>fragment</i>]
 * </blockquote>
 *
 * where the characters <tt><b>:</b></tt>, <tt><b>/</b></tt>,
 * <tt><b>?</b></tt>, and <tt><b>#</b></tt> stand for themselves.  The
 * scheme-specific part of a hierarchical URI consists of the characters
 * between the scheme and fragment components.
 *
 * <p> The authority component of a hierarchical URI is, if specified, either
 * <i>server-based</i> or <i>registry-based</i>.  A server-based authority
 * parses according to the familiar syntax
 *
 * <blockquote>
 * [<i>user-info</i><tt><b>@</b></tt>]<i>host</i>[<tt><b>:</b></tt><i>port</i>]
 * </blockquote>
 *
 * where the characters <tt><b>@</b></tt> and <tt><b>:</b></tt> stand for
 * themselves.  Nearly all URI schemes currently in use are server-based.  An
 * authority component that does not parse in this way is considered to be
 * registry-based.
 *
 * <p> The path component of a hierarchical URI is itself said to be absolute
 * if it begins with a slash character (<tt>'/'</tt>); otherwise it is
 * relative.  The path of a hierarchical URI that is either absolute or
 * specifies an authority is always absolute.
 *
 * <p> All told, then, a URI instance has the following nine components:
 *
 * <blockquote><table>
 * <tr><td><i>Component</i></td><td><i>Type</i></td></tr>
 * <tr><td>scheme</td><td><tt>String</tt></td></tr>
 * <tr><td>scheme-specific-part&nbsp;&nbsp;&nbsp;&nbsp;</td><td><tt>String</tt></td></tr>
 * <tr><td>authority</td><td><tt>String</tt></td></tr>
 * <tr><td>user-info</td><td><tt>String</tt></td></tr>
 * <tr><td>host</td><td><tt>String</tt></td></tr>
 * <tr><td>port</td><td><tt>int</tt></td></tr>
 * <tr><td>path</td><td><tt>String</tt></td></tr>
 * <tr><td>query</td><td><tt>String</tt></td></tr>
 * <tr><td>fragment</td><td><tt>String</tt></td></tr>
 * </table></blockquote>
 *
 * In a given instance any particular component is either <i>undefined</i> or
 * <i>defined</i> with a distinct value.  Undefined string components are
 * represented by <tt>null</tt>, while undefined integer components are
 * represented by <tt>-1</tt>.  A string component may be defined to have the
 * empty string as its value; this is not equivalent to that component being
 * undefined.
 *
 * <p> Whether a particular component is or is not defined in an instance
 * depends upon the type of the URI being represented.  An absolute URI has a
 * scheme component.  An opaque URI has a scheme, a scheme-specific part, and
 * possibly a fragment, but has no other components.  A hierarchical URI always
 * has a path (though it may be empty) and a scheme-specific-part (which at
 * least contains the path), and may have any of the other components.  If the
 * authority component is present and is server-based then the host component
 * will be defined and the user-information and port components may be defined.
 * 
 * See <a href="http://www.isi.edu/in-notes/rfc2396.txt""><i>RFC&nbsp;2396:
 * Uniform Resource Identifiers (URI): Generic Syntax</i></a>
 *
 */
class URITransformer {

	/**
	 * Array containing the safe characters set for encoding.
	 * <p>
	 * Only the following characters are not encoded:<br>
	 * A-Z a-z 0-9 : @ & $ - _ . + ! * ' ( ) ,
	 * </p>
	 */
	protected static BitSet safeCharacters;


	static {
		safeCharacters = new BitSet(256);
		int i;
		for (i = 'a'; i <= 'z'; i++) {
			safeCharacters.set(i);
		}
		for (i = 'A'; i <= 'Z'; i++) {
			safeCharacters.set(i);
		}
		for (i = '0'; i <= '9'; i++) {
			safeCharacters.set(i);
		}
		safeCharacters.set('=');
		safeCharacters.set(':');
		safeCharacters.set('@');
		safeCharacters.set('&');
		safeCharacters.set('$');
		safeCharacters.set('-');
		safeCharacters.set('_');
		safeCharacters.set('.');
		safeCharacters.set('+');
		safeCharacters.set('!');
		safeCharacters.set('*');
		safeCharacters.set('\'');
		safeCharacters.set('(');
		safeCharacters.set(')');
		safeCharacters.set(',');
	}

	/**
	 * Encode path to be used as path component segments in URI.
	 *
	 * <p>Creates a String that can be used as a sequence of one or more
	 * path components in an URI from a path that uses a slash
	 * character as a path separator and where the segements do not use
	 * any URI encoding rules.</p>
	 *
	 * <p>The <b>/</b> characters (delimiting the individual path_segments)
	 * are left unchanged.</p>
	 *
	 * @param path A path that is not using URI encoding rules.
	 * @return A path that is using URI encoding rules.
	 *
	 * @see #decodePath(String)
	 */
	public static String encodePath(String path) {
		try {
			StringBuilder pathc = new StringBuilder();
			byte[] bytes = null;
			bytes = path.getBytes("UTF-8");
			for (int i = 0; i < bytes.length; i++) {
				int v = bytes[i];
				if (v < 0) {
					v += 256;
				}
				if (v > 0 && v < 256 && safeCharacters.get(v)) {
					pathc.append((char) v);
				} else if ((char) v == '/') {
					pathc.append((char) v);
				} else {
					pathc.append("%" + Integer.toHexString(v));
				}
			}
			path = pathc.toString();
		} catch (UnsupportedEncodingException ex) {
			Logger.getLogger(URITransformer.class.getName()).log(Level.SEVERE, null, ex);
		}
		return path;
	}

	/**
	 * Decode path component segments in URI.
	 *
	 * <p>Creates a path that uses a slash character as a path separator
	 * and where the segments do not use any URI encoding
	 * from a String that is used as a sequence of one or more
	 * path components in an URI where the path segments do use
	 * URI encoding rules.</p>
	 *
	 * <p>The <b>/</b> characters (delimiting the individual path_segments)
	 * are left unchanged.</p>
	 *
	 * @param path A path that is using URI encoding rules.
	 * @return A path that is not using URI encoding rules.
	 *
	 * @see #encodePath(String)
	 *
	 */
	public static String decodePath(String path) {
		String pathc = path;
		StringBuilder uri = new StringBuilder();

		int j = pathc.indexOf('%', 0);
		int l = pathc.length();

		ByteArrayOutputStream ba = new ByteArrayOutputStream();
		byte[] b = {0};
		while (j != -1) {
			if (j + 3 <= l) {
				try {
					b = pathc.substring(0, j).getBytes("UTF-8");
					ba.write(b, 0, b.length);
				} catch (java.io.UnsupportedEncodingException e) {
				}
				String hex = pathc.substring(j + 1, j + 3);
				try {
					int n = Integer.parseInt(hex, 16);
					ba.write(n);
				} catch (NumberFormatException e) {
					String tmp = "=" + hex;
					try {
						b = tmp.getBytes("UTF-8");
					} catch (java.io.UnsupportedEncodingException e2) {
					}
					ba.write(b, 0, b.length);
				}
				pathc = pathc.substring(j + 3);
				l = pathc.length();
				j = pathc.indexOf('%', 0);
			} else {
				j = -1;
			}
		}
		try {
			uri.append(new String(ba.toByteArray(), "UTF-8"));
		} catch (java.io.UnsupportedEncodingException e2) {
		}

		uri.append(pathc);

		return uri.toString();
	}

	/**
	 * Extract URI from a path.
	 *
	 * <p>Transforms a path that was created with the
	 * {@link #uri2path(String)} method back to an URI.</p>
	 *
	 * <p>This method does try to cope with an erroneous
	 * input parameter but the result returned in such a case is not
	 * guaranteed to be a valid URI.</p>
	 *
	 * @param path the path that contains the URI information
	 * @return a String representing a URI
	 *
	 * @see #uri2path(String)
	 */
	public static String path2uri(String path) {

		if (path == null) {
			return null;
		}
		StringBuilder uri = new StringBuilder();
		String npath;
		// ignore leading slash
		if (path.startsWith("/")) {
			npath = path.substring(1);
		} else {
			npath = path;
		}

		int l = npath.length();

		int i = npath.indexOf('/');
		if (i == -1) {
			if (npath.equals("")) {
				return npath;
			}
			return npath + "://";
		}

		String rpath = "";
		boolean bauth = true;

		if (i == 0) {
			uri.append("/");
		} else {

			String scheme;
			if (i == l) {
				return npath + "://";
			}
			scheme = npath.substring(0, i) + ":";
			if (i + 4 <= l) {
				String hier = npath.substring(i + 1, i + 4);
				if (hier.startsWith("==0/")) {
					i += 5;
				} else if (hier.startsWith("==0")) {
					i += 4;
				} else if (hier.startsWith("==1")) {
					bauth = false;
					scheme += "";
					i += 3;
				} else if (hier.startsWith("==2")) {
					scheme += "//";
					i += 3;
					bauth = false;
				} else {
					scheme += "//";
				}

			}
			uri.append(scheme);
		}


		int j = -1;
		String auth = "";

		if (bauth) {
			if (rpath.equals("")) {
				if (i + 1 <= l) {
					j = npath.indexOf('/', i + 1);
				}

				if (j == -1) {
					j = l;
				} else {
					rpath = npath.substring(j);
				}
				if (i + 1 <= l) {
					auth = npath.substring(i + 1, j);
				} else {
					auth = "";
				}
			} else {
				if (i + 1 <= l) {
					rpath = rpath + npath.substring(i + 1);
				} else {
					rpath = "";
				}
			}

			j = auth.indexOf('=', 0);
			l = auth.length();

			ByteArrayOutputStream ba = new ByteArrayOutputStream();
			byte[] b = {0};
			while (j != -1) {
				if (j + 3 <= l) {
					try {
						b = auth.substring(0, j).getBytes("UTF-8");
						ba.write(b, 0, b.length);
					} catch (java.io.UnsupportedEncodingException e) {
					}
					String hex = auth.substring(j + 1, j + 3);
					try {
						int n = Integer.parseInt(hex, 16);
						ba.write(n);
					} catch (NumberFormatException e) {
						String tmp = "=" + hex;
						try {
							b = tmp.getBytes("UTF-8");
						} catch (java.io.UnsupportedEncodingException e2) {
						}
						ba.write(b, 0, b.length);
					}
					auth = auth.substring(j + 3);
					l = auth.length();
					j = auth.indexOf('=', 0);
				} else {
					j = -1;
				}
			}
			try {
				uri.append(new String(ba.toByteArray(), "UTF-8"));
			} catch (java.io.UnsupportedEncodingException e2) {
			}
			uri.append(auth);

		} else {
			if (i + 1 <= l) {
				rpath = npath.substring(i + 1); // empty authority
			} else {
				rpath = "";
			}
		}

		uri.append(encodePath(rpath));

		return uri.toString();
	}

	/**
	 * Embed URI into path.
	 *
	 * <h4>Opaque URIs</h4>
	 *
	 * Opaque URIs are mapped to a <i>path</i> of the form
	 * &lt;<b>/</b> <i>scheme</i> <b>/==0/</b> <i>opaque_part'</i>&gt;.</p>
	 * </p>
	 * <p>The mapping from <i>opaque_part</i> to <i>opaque_part'</i>
	 * works as follows:(*)<p>
	 *
	 * <p>Octets from the set <b>A-Z a-z 0-9 : @ & $ - _ . + ! * ' ( ) ,</b>
	 * are left unchanged.</p>
	 *
	 * <p>Other octest are replaced with <b>=</b> followed by two hex digits
	 * that represent the octet's numerical value.</p>
	 *
	 * <h4>Hierarchical URIs without an <i>authority</i> component</h4>
	 *
	 * <p>Hierarchical URIs without an <i>authority</i> component
	 * are mapped to a <i>path</i> of the form
	 * &lt;<b>/</b> <i>scheme</i> <b>/==1</b> <i>abs_path</i>' [<b>?</b>
	 * <i>query</i>]&gt;.</p>
	 *
	 * <p>If <i>abs_path</i> is empty, it is left unchanged.</p>
	 *
	 * <p>If <i>abs_path</i> is non-empty, it is decoded with
	 * the {@link #decodePath(String)} method.</p>
	 *
	 * <p>A non-empty path_segment is left unchanged.</p>
	 *
	 * <h4>Hierarchical URIs with an <i>authority</i> component</h4>
	 * <p>Hierarchical URIs with an <i>authority</i> component
	 * <b>?</b> query]&gt; are mapped to a <i>path</i> of the
	 * form &lt;<b>/</b> <i>scheme</i> <b>/</b> <i>authority'</i>
	 * <i>abs_path'</i> [<b>?</b><i>query</i>]&gt;.</p>
	 *
	 * <p>If <i>authority</i> is empty, it is mapped to
	 * <b>==2</b>. This eliminates
	 * problems if the servlet container drops final slashes
	 * from <i>paths</i> or cannot handle empty segments
	 * within <i>paths.</i></p>
	 *
	 * <p>The mapping from <i>abs_path</i> to <i>abs_path'</i>
	 * works as follows:</p>
	 *
	 * </p>
	 * <p>If <i>authority</i> is non-empty, it is mapped as described
	 * for the <i>opaque_part</i> above.</p>
	 *
	 * <p>The mapping from <i>abs_path</i> to <i>abs_path'</i>
	 * works as follows:</p>
	 *
	 * <p>If <i>abs_path</i> is empty, it is left unchanged.</p>
	 *
	 * <p>If <i>abs_path</i> is non-empty, it is decoded with
	 * the {@link #decodePath(String)} method.</p>
	 *
	 * @see #path2uri(String)
	 */
	public static String uri2path(String uri) {
		if (uri == null) {
			return null;
		}
		StringBuilder path = new StringBuilder();
		int i = uri.indexOf(":");
		if (i == -1) {
			return uri;
		}
		int l = uri.length();

		path.append(uri.substring(0, i)).append("/");

		int sc = 0;
		if ((i + 3 <= l) && uri.substring(i + 1, i + 3).equals("//")) {
			i += 3;
			sc = 2;
		} else if ((i + 2 <= l) && uri.substring(i + 1, i + 2).equals("/")) {
			i += 2;
			sc = 1;
		} else {
			i++;
		}

		int j = uri.indexOf('/', i);
		String ruri = "";
		if (j == -1) {
			j = l;
			ruri = "";
		} else {
			ruri = uri.substring(j);
		}
		String auth = uri.substring(i, j);

		if (sc == 2 && auth.length() == 0) {
			path.append("==2");
		} else if (sc == 1) {
			path.append("==1/");
		} else if (sc == 0) {
			path.append("==0/");
		}

		byte[] bytes = null;
		try {
			bytes = auth.getBytes("UTF-8");
		} catch (java.io.UnsupportedEncodingException e) {
		}
		for (i = 0; i < bytes.length; i++) {
			int v = bytes[i];
			if (v < 0) {
				v += 256;
			}
			if (v > 0 && v < 256 && safeCharacters.get(v)) {
				path.append((char) v);
			} else {
				path.append("=" + Integer.toHexString(v));
			}
		}

		path.append(decodePath(ruri));
		return path.toString();
	}

	private URITransformer() {
	}
}

