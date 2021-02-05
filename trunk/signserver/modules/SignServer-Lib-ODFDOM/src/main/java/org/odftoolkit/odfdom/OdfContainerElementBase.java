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

//2DO: Move into tooling package?
package org.odftoolkit.odfdom;

import org.odftoolkit.odfdom.OdfElement;
import org.odftoolkit.odfdom.OdfFileDom;
import org.w3c.dom.DOMException;
import org.w3c.dom.Node;

/**
 * base class for elements that want to be notified when OdfElement child
 * nodes are removed or inserted.
 */
abstract public class OdfContainerElementBase extends OdfElement
{
    /**
	 * 
	 */
	private static final long serialVersionUID = 6944696143015713668L;

	/** Creates a new instance of OdfElement */
    public OdfContainerElementBase(OdfFileDom ownerDocument,
            String namespaceURI,
            String qualifiedName) throws DOMException {
        super(ownerDocument, namespaceURI, qualifiedName);
    }

    /** Creates a new instance of OdfElement */
    public OdfContainerElementBase(OdfFileDom ownerDocument, 
            OdfName aName) throws DOMException {
        super(ownerDocument, aName.getUri(), aName.getQName());
    }    
    
    /** override this method to get notified about element insertion
     */
    abstract protected void onOdfNodeInserted( OdfElement node, Node refChild );
            
    /** override this method to get notified about element insertion
     */
    abstract protected void onOdfNodeRemoved( OdfElement node );

    @Override
    public Node insertBefore(Node newChild, Node refChild) throws DOMException
    {
        Node ret = super.insertBefore(newChild, refChild);

        if( newChild instanceof OdfElement )
            onOdfNodeInserted( (OdfElement) newChild, refChild );
        
        return ret;
    }

    @Override
    public Node removeChild(Node oldChild) throws DOMException
    {
        Node ret = super.removeChild(oldChild);
        
        if( oldChild instanceof OdfElement )
            onOdfNodeRemoved( (OdfElement) oldChild );
        
        return ret;
    }

    @Override
    public Node replaceChild(Node newChild, Node oldChild) throws DOMException
    {
        Node ret = super.replaceChild(newChild, oldChild);

        if( newChild instanceof OdfElement )
            onOdfNodeInserted( (OdfElement) newChild, oldChild );

        if( oldChild instanceof OdfElement )
            onOdfNodeRemoved( (OdfElement) oldChild );

        return ret;
    }

}
