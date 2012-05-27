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
package org.odftoolkit.odfdom;

import org.odftoolkit.odfdom.OdfNamespace;
import org.odftoolkit.odfdom.dom.*;
import java.util.HashMap;

public class OdfName implements Comparable<OdfName> {
    
    private OdfNamespace m_ns;
    private String m_localname;
    private String m_fullstring;
    // private static TreeSet<OdfName> m_names = new TreeSet<OdfName>();
    private static HashMap<String, OdfName> m_names = new HashMap<String, OdfName>();

    private void init(OdfNamespace ns, String localname) {
        m_ns = ns;
        m_localname = localname;
        StringBuilder b = new StringBuilder();
        b.append('{');
        b.append(m_ns.toString());
        b.append('}');
        b.append(m_localname);
        m_fullstring = b.toString();
    }
    
    private OdfName(OdfNamespace ns, String localname) {
        int i = 0;
        if ((i = localname.indexOf(':'))>=0) {
            localname = localname.substring(i+1);
        }
        init(ns, localname);
    }
    
    private OdfName(String uri, String qname) {
        String[] qnpair = OdfNamespace.splitQName(qname);
        OdfNamespace ns = OdfNamespace.get(qnpair[0], uri);
        init(ns, qnpair[1]);
    }
    
    public static OdfName get(OdfName name) {
        OdfName n = m_names.get(name.toString());
        if (n != null) {
            return n;
        } else {
            m_names.put(name.toString(), name);
            return name;
        }
    }
    
    public static OdfName get(OdfNamespace ns, String localname) {
        return get(new OdfName(ns, localname));
    }
    
    public static OdfName get(OdfNamespaceNames nsname, String localname) {
        return get(new OdfName(OdfNamespace.get(nsname), localname));
    }

    public static OdfName get(String uri, String localname) {
        return get(new OdfName(uri, localname));
    }
    
    public String getUri() {
        return m_ns.getUri();
    }
    
    public String getLocalName() {
        return m_localname;
    }
    
    public String getQName() {
        if (m_ns.hasPrefix())
            return m_ns.getPrefix() + ":" + m_localname;
        else
            return m_localname;
    }
    
    @Override
	public String toString() {
        return m_fullstring;
    }
    
    @Override
	public boolean equals(Object obj) { 
        if (obj != null)
            return toString().equals(obj.toString());
        else
            return false;
    }
    
    public boolean equals(String uri, String local_name)
    {
        if( !m_ns.getUri().equals(uri) )
            return false;
        
        int beginIndex = local_name.indexOf(':');
        if( beginIndex >= 0 )
        {
            return m_localname.equals( local_name.substring(beginIndex+1));
        }
        else
        {
            return m_localname.equals( local_name );           
        }
    }    
    
    @Override
	public int hashCode() {
       return toString().hashCode();
    }

    public int compareTo(OdfName o) {
        return toString().compareTo(o.toString());
    }
}
