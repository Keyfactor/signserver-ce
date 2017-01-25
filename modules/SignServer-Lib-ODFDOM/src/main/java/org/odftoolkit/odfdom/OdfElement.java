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

import java.util.ArrayList;
import org.apache.xerces.dom.ElementNSImpl;
import org.apache.xerces.dom.ParentNode;
import org.odftoolkit.odfdom.doc.OdfDocument;
import org.odftoolkit.odfdom.dom.OdfNamespaceNames;
import org.odftoolkit.odfdom.OdfFileDom;
import org.odftoolkit.odfdom.OdfNamespace;
import org.w3c.dom.DOMException;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

//2DO: Refactor public to package viewer, when inheritance is exchanged from OdfElement to specific Odf Element
abstract public class OdfElement extends ElementNSImpl {

    /**
	 * 
	 */
	private static final long serialVersionUID = -4939293285696678939L;
	// the OdfDocument containing the element
    protected OdfDocument mOdfDocument;

    /** Creates a new instance of OdfElement */
    public OdfElement(OdfFileDom ownerDocument,
            String namespaceURI,
            String qualifiedName) throws DOMException {
        super(ownerDocument, namespaceURI, qualifiedName);
        mOdfDocument = ownerDocument.getOdfDocument();
    }

    /** Creates a new instance of OdfElement */
    public OdfElement(OdfFileDom ownerDocument, 
            OdfName aName) throws DOMException {
        super(ownerDocument, aName.getUri(), aName.getQName());
        mOdfDocument = ownerDocument.getOdfDocument();
    }
    
    abstract public OdfName getOdfName();
    
    protected <T extends OdfElement> T getParentAs(Class<T> clazz) {
        Node parent = getParentNode();
        if (parent != null && clazz.isInstance(parent)) {
            return clazz.cast(parent);
        } else {
            return null;
        }
    }

    protected <T extends OdfElement> T getAncestorAs(Class<T> clazz) {
        Node node = getParentNode();        
        while ( node != null) {
            if (clazz.isInstance(node)) {
                return clazz.cast(node);
            }
            node = node.getParentNode();
        }
        return null;
    }    
    
    @Override
    public String toString(){
        return mapNode(this, new StringBuilder()).toString();
    }
    
    /** Only Siblings will be traversed by this method as Children */
    static private StringBuilder mapNodeTree(Node node, StringBuilder xml){
        while(node != null){
            // mapping node and this mapping include always all descendants
            xml = mapNode(node, xml);
            // next sibling will be mapped to XML
            node = node.getNextSibling();
        }
        return xml;
    }
        
    private static StringBuilder mapNode(Node node, StringBuilder xml){
        if(node instanceof Element){
            xml = mapElementNode(node, xml);
        }else if(node instanceof Text){
            xml = mapTextNode(node, xml);
        }
        return xml;
    }
    
    private static StringBuilder mapTextNode(Node node, StringBuilder xml){
        if(node != null){
            xml = xml.append(node.getTextContent());
        }
        return xml;
    }
        
    private static StringBuilder mapElementNode(Node node, StringBuilder xml){
        if(node != null){
            xml = xml.append("<");
            xml = xml.append(node.getNodeName());
            xml = mapAttributeNode(node, xml);
            xml = xml.append(">");
            xml = mapNodeTree(node.getFirstChild(), xml);
            xml = xml.append("</");
            xml = xml.append(node.getNodeName());
            xml = xml.append(">");
        }
        return xml;
    }
    
    private static StringBuilder mapAttributeNode(Node node, StringBuilder xml){
        NamedNodeMap attrs = null;
        int length;
        if((attrs = node.getAttributes()) != null && (length = attrs.getLength()) > 0){
            for(int i=0;length > i;i++){
                xml = xml.append(" ");
                xml = xml.append(attrs.item(i).getNodeName());
                xml = xml.append("=\"");
                xml = xml.append(attrs.item(i).getNodeValue());
                xml = xml.append("\"");
            }
        }
        return xml;
    }   

    /**
     * Set the value of an ODF attribute by <code>OdfName</code>.
     *
     * @param name The qualified name of the ODF attribute.
     * @param value The value to be set in <code>String</code> form
     */
    public void setOdfAttributeValue(OdfName name, String value) {
        setAttributeNS(name.getUri(), name.getQName(), value);
    }
    
    /**
     * Set an ODF attribute to this element
     * @param attribute	the attribute to be set
     */
    public void setOdfAttribute( OdfAttribute attribute ) {
        setAttributeNodeNS(attribute);
    }
    

    /**
     * Retrieves a value of an ODF attribute by <code>OdfName</code>.
     *
     * @param name The qualified name of the ODF attribute.
     * @return The value of the attribute as <code>String</code> or <code>null</code> if the attribute does not exist.
     */
    public String getOdfAttributeValue(OdfName name) {
        return getAttributeNS(name.getUri(), name.getLocalName());
    }

    /**
     * Retrieves an ODF attribute by <code>OdfName</code>.
     *
     * @param name The qualified name of the ODF attribute.
     * @return The <code>OdfAttribute</code> or <code>null</code> if the attribute does not exist.
     */
    public OdfAttribute getOdfAttribute(OdfName name){
        return (OdfAttribute) getAttributeNodeNS(name.getUri(), name.getLocalName());
    }

    /**
     * Determines if an ODF attribute exists.
     *
     * @param name The qualified name of the ODF attribute.
     * @return True if the attribute exists.
     */
    public boolean hasOdfAttribute(OdfName name) {
        return hasAttributeNS(name.getUri(), name.getLocalName());
    }
    
    /** returns the first child node that implements the given class.
     * 
     * @param <T> The type of the ODF element to be found.
     * @param clazz is a class that extends OdfElement.
     * @param parentNode is the parent O of the children to be found.
     * @return the first child node of the given parentNode that is a clazz or null if none is found.
     */
    @SuppressWarnings("unchecked")
    static public <T extends OdfElement> T findFirstChildNode( Class<T> clazz, Node parentNode )
    {
        if( parentNode != null && parentNode instanceof ParentNode )
        {
            Node node = ((ParentNode)parentNode).getFirstChild();
            while( (node != null) && !clazz.isInstance(node) ) {
                node = node.getNextSibling();
            }        

            if( node != null ) {
                return (T) node;
            }
        }
        
        return null;
    }
    
    /** returns the first sibling after the given reference node that implements the given class.
     * 
     * @param <T> The type of the ODF element to be found.
     * @param clazz is a class that extends OdfElement.
     * @param refNode the reference node of the siblings to be found.
     * @return the first sibbling of the given reference node that is a clazz or null if none is found.
     */
    @SuppressWarnings("unchecked")
    static public <T extends OdfElement> T findNextChildNode( Class<T> clazz, Node refNode )
    {
        if( refNode != null )
        {
            Node node = refNode.getNextSibling();
            while( node != null && !clazz.isInstance(node) ) {
                node = node.getNextSibling();
            }        

            if( node != null ) {
                return (T) node;
            }
        }
        
        return null;
    }
    
    /** returns the first previous sibling before the given reference node that implements the given class.
     * 
     * @param clazz is a class that extends OdfElement.
     * @param refNode the reference node which siblings are to be searched.
     * @return the first previous sibbling of the given reference node that is a clazz or null if none is found.
     */
    @SuppressWarnings("unchecked")
    static public <T extends OdfElement> T findPreviousChildNode( Class<T> clazz, Node refNode )
    {
        if( refNode != null )
        {
            Node node = refNode.getPreviousSibling();
            while( node != null && !clazz.isInstance(node) )
                node = node.getPreviousSibling();

            if( node != null )
                return (T)node;
        }
        
        return null;
    }    
    
    @Override
    public Node cloneNode( boolean deep )
    {
        OdfElement cloneElement = ((OdfFileDom) this.ownerDocument).createElementNS(getOdfName());
                
        if( attributes != null )
        {
            for( int i = 0; i < attributes.getLength(); i++ )
            {
                Node item = attributes.item(i);
                cloneElement.setAttributeNS(item.getNamespaceURI(), item.getLocalName(), item.getNodeValue() );            
            }
        }
        
        if( deep )
        {
            Node childNode = getFirstChild();
            while( childNode != null )
            {
                cloneElement.appendChild( childNode.cloneNode(true) );
                childNode = childNode.getNextSibling();
            }
        }
        
        return cloneElement;
    }
    
    /** indicates if some other object is equal to this one.
     *
     * @param obj - the reference object with which to compare.
     * @return true if this object is the same as the obj argument; false otherwise.
     */
    @Override
    public boolean equals(Object obj)
    {
        if( this == obj )
            return true;

        if( (obj == null) || !(obj instanceof OdfElement) )
            return false;

        OdfElement compare = (OdfElement)obj;

        // compare node name
        if( !localName.equals( compare.localName ) )
           return false;

        if( !this.namespaceURI.equals( compare.namespaceURI ) )
            return false;

        // compare node attributes
        if( attributes == compare.attributes )
            return true;

        if( (attributes == null) || (compare.attributes == null) )
            return false;

        int attr_count1 = attributes.getLength();
        int attr_count2 = compare.attributes.getLength();

        ArrayList< Node > attr1 = new ArrayList< Node >();
        for( int i = 0; i < attr_count1; i++ )
        {
            Node node = attributes.item(i);
            if( node.getNodeValue().length() == 0 )
                continue;
            attr1.add( node );
        }

        ArrayList< Node > attr2 = new ArrayList< Node >();
        for( int i = 0; i < attr_count2; i++ )
        {
            Node node = compare.attributes.item(i);
            if( node.getNodeValue().length() == 0 )
                continue;
            attr2.add( node );
        }

        if( attr1.size() != attr2.size() )
            return false;

        for( int i = 0; i < attr1.size(); i++ )
        {
            Node n1 = attr1.get(i);
            if( n1.getLocalName().equals( "name") && n1.getNamespaceURI().equals( OdfNamespaceNames.STYLE.getNamespaceUri()) )
                continue; // do not compare style names

            Node n2 = null;
            int j = 0;
            for( j = 0; j < attr2.size(); j++ )
            {
                n2 = attr2.get(j);
                if( n1.getLocalName().equals(n2.getLocalName()) && n1.getNamespaceURI().equals(n2.getNamespaceURI()) )
                    break;
            }
            if( j == attr2.size() )
                return false;

            if( !n1.getTextContent().equals( n2.getTextContent()))
                return false;
        }

        // now compare child elements
        NodeList childs1 = this.getChildNodes();
        NodeList childs2 = compare.getChildNodes();

        int child_count1 = childs1.getLength();
        int child_count2 = childs2.getLength();
        if( (child_count1 == 0) && (child_count2 == 0 ))
            return true;

        ArrayList< Node > nodes1 = new ArrayList< Node >();
        for( int i = 0; i < child_count1; i++ )
        {
            Node node = childs1.item(i);
            if( node.getNodeType() == Node.TEXT_NODE )
                if( node.getNodeValue().trim().length() == 0 )
                    continue; // skip whitespace text nodes

            nodes1.add( node );
        }

        ArrayList< Node > nodes2 = new ArrayList< Node >();
        for( int i = 0; i < child_count2; i++ )
        {
            Node node = childs2.item(i);
            if( node.getNodeType() == Node.TEXT_NODE )
                if( node.getNodeValue().trim().length() == 0 )
                    continue; // skip whitespace text nodes

            nodes2.add( node );
        }

        if( nodes1.size() != nodes2.size() )
            return false;

        for( int i = 0; i < nodes1.size(); i++ )
        {
            Node n1 = nodes1.get(i);
            Node n2 = nodes2.get(i);
            if( !n1.equals(n2) )
                return false;
        }
        return true;
    }

    protected void onRemoveNode( Node node )
    {
        Node child = node.getFirstChild();
        while( child != null )
        {
            this.onRemoveNode( child );
            child = child.getNextSibling();
        }

        if( OdfElement.class.isInstance( node ) )
            ((OdfElement)node).onRemoveNode();
    }

    protected void onInsertNode( Node node )
    {
        Node child = node.getFirstChild();
        while( child != null )
        {
            this.onInsertNode( child );
            child = child.getNextSibling();
        }

        if( OdfElement.class.isInstance( node ) )
            ((OdfElement)node).onInsertNode();
    }

    protected void onRemoveNode()
    {
    }

    protected void onInsertNode()
    {
    }

    @Override
    public Node insertBefore(Node newChild, Node refChild) throws DOMException
    {
        onInsertNode(newChild);
        return super.insertBefore(newChild, refChild);
    }

    @Override
    public Node removeChild(Node oldChild) throws DOMException
    {
        onRemoveNode(oldChild);
        return super.removeChild(oldChild);
    }

    @Override
    public Node replaceChild(Node newChild, Node oldChild) throws DOMException
    {
        onInsertNode(newChild);
        onRemoveNode(oldChild);
        return super.replaceChild(newChild, oldChild);
    }
}
