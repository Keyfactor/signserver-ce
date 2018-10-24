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
package org.signserver.server;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility methods for dealing with cookie encoding/decoding.
 * 
 * From RFC6265 section 4.1.1:
 * <pre>
 * cookie-pair       = cookie-name "=" cookie-value
 * cookie-name       = token
 * cookie-value      = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )
 * cookie-octet      = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
 *                      ; US-ASCII characters excluding CTLs,
 *                      ; whitespace, DQUOTE, comma, semicolon,
 *                      ; and backslash
 * token             = &lt;token, defined in [RFC2616], Section 2.2&gt;
 * </pre>
 * 
 * From RFC2616 section 2.2:
 * <pre>
 *      token          = 1*&lt;any CHAR except CTLs or separators&gt;
 *      separators     = "(" | ")" | "&lt;" | "&gt;" | "@"
 *                     | "," | ";" | ":" | "\" | &lt;"&gt;
 *                     | "/" | "[" | "]" | "?" | "="
 *                     | "{" | "}" | SP | HT
 * </pre>
 * 
 * From RFC5254:
 * <pre>
 *      CTL            =  %x00-1F / %x7F
 *                              ; controls
 * </pre>
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class CookieUtils {

    private CookieUtils() {}
    
    public static String toCookiePair(String name, String value) {
        return toCookieName(name) + "=" + toCookieValue(value).replace("=", "%3D").replace("(", "%28").replace(")", "%29");
    }
    
    public static String toCookieName(String name) {
        // TODO
        return name;
    }
    
    public static String fromCookieName(String cookieName) {
        // TODO
        return cookieName;
    }
    
    public static String toCookieValue(String value) {
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            //final int cp = value.codePointAt(i);
            final char cp = value.charAt(i);
            
            if (!isWorkaroundRequiredFor(cp) && (cp == 0x21 || (cp >= 0x23 && cp <= 0x2B) || (cp >= 0x2D && cp <= 0x3A) || (cp >= 0x3C && cp <= 0x5B) || (cp >= 0x5D && cp <= 0x7E))) {
                sb.append(cp);
            } else {
                sb.append("%").append(String.format("%02X", (int) cp));
            }
        }
        return sb.toString();
    }
    
    private static boolean isWorkaroundRequiredFor(char cp) { // TODO: Consider skipping this
        return cp == '=' || cp == '(' || cp == ')' || cp == '@';
    }

    public static String fromCookieValue(String cookieOctet) {
        String result = cookieOctet;
        
        // Match on procent-encoded values (i.e. "%00-%FF")
        final Pattern pattern = Pattern.compile("(%[0-9A-Fa-f]{2})");
        final Matcher matcher = pattern.matcher(cookieOctet);
        
        // As long as there is a match
        while (matcher.find()) {
            String procentEncoded = matcher.group();
            
            // Replace the procent-encoded value with the actual character
            char c = (char) Integer.parseInt(procentEncoded.substring(1), 16);
            result = result.replace(procentEncoded, new String(new char[] {c}));
        }        
        
        return result;
    }
    
}
