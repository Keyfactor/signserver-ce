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
package org.odftoolkit.odfdom.dom.element;

import org.odftoolkit.odfdom.OdfAttribute;
import org.odftoolkit.odfdom.OdfContainerElementBase;
import org.odftoolkit.odfdom.OdfElement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;

import org.odftoolkit.odfdom.OdfFileDom;
import org.odftoolkit.odfdom.doc.style.OdfStyleParagraphProperties;
import org.odftoolkit.odfdom.doc.style.OdfStyleTextProperties;
import org.odftoolkit.odfdom.OdfName;
import org.odftoolkit.odfdom.dom.OdfNamespaceNames;
import org.odftoolkit.odfdom.dom.element.style.StyleChartPropertiesElement;
import org.odftoolkit.odfdom.dom.element.style.StyleDrawingPagePropertiesElement;
import org.odftoolkit.odfdom.dom.element.style.StyleGraphicPropertiesElement;
import org.odftoolkit.odfdom.dom.element.style.StyleHeaderFooterPropertiesElement;
import org.odftoolkit.odfdom.dom.element.style.StyleListLevelPropertiesElement;
import org.odftoolkit.odfdom.dom.element.style.StylePageLayoutPropertiesElement;
import org.odftoolkit.odfdom.dom.element.style.StyleParagraphPropertiesElement;
import org.odftoolkit.odfdom.dom.element.style.StyleRubyPropertiesElement;
import org.odftoolkit.odfdom.dom.element.style.StyleSectionPropertiesElement;
import org.odftoolkit.odfdom.dom.element.style.StyleTableCellPropertiesElement;
import org.odftoolkit.odfdom.dom.element.style.StyleTableColumnPropertiesElement;
import org.odftoolkit.odfdom.dom.element.style.StyleTablePropertiesElement;
import org.odftoolkit.odfdom.dom.element.style.StyleTableRowPropertiesElement;
import org.odftoolkit.odfdom.dom.element.style.StyleTextPropertiesElement;
import org.odftoolkit.odfdom.dom.style.OdfStyleFamily;
import org.odftoolkit.odfdom.dom.style.OdfStylePropertySet;
import org.odftoolkit.odfdom.dom.style.props.OdfStylePropertiesSet;
import org.odftoolkit.odfdom.dom.style.props.OdfStyleProperty;
import org.w3c.dom.Attr;
import org.w3c.dom.DOMException;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 *
 */
abstract public class OdfStyleBase extends OdfContainerElementBase implements OdfStylePropertySet, Comparable {

    /**
     *
     */
    private static final long serialVersionUID = 8271282184913774000L;
    private HashMap<OdfStylePropertiesSet, OdfStylePropertiesBase> mPropertySetElementMap;
    private ArrayList<OdfStylableElement> mStyleUser;
    static HashMap<OdfName, OdfStylePropertiesSet> mStylePropertiesElementToSetMap;


    static {
        mStylePropertiesElementToSetMap = new HashMap<OdfName, OdfStylePropertiesSet>();
        mStylePropertiesElementToSetMap.put(StyleChartPropertiesElement.ELEMENT_NAME, OdfStylePropertiesSet.ChartProperties);
        mStylePropertiesElementToSetMap.put(StyleDrawingPagePropertiesElement.ELEMENT_NAME, OdfStylePropertiesSet.DrawingPageProperties);
        mStylePropertiesElementToSetMap.put(StyleGraphicPropertiesElement.ELEMENT_NAME, OdfStylePropertiesSet.GraphicProperties);
        mStylePropertiesElementToSetMap.put(StyleHeaderFooterPropertiesElement.ELEMENT_NAME, OdfStylePropertiesSet.HeaderFooterProperties);
        mStylePropertiesElementToSetMap.put(StyleListLevelPropertiesElement.ELEMENT_NAME, OdfStylePropertiesSet.ListLevelProperties);
        mStylePropertiesElementToSetMap.put(StylePageLayoutPropertiesElement.ELEMENT_NAME, OdfStylePropertiesSet.PageLayoutProperties);
        mStylePropertiesElementToSetMap.put(StyleParagraphPropertiesElement.ELEMENT_NAME, OdfStylePropertiesSet.ParagraphProperties);
        mStylePropertiesElementToSetMap.put(StyleRubyPropertiesElement.ELEMENT_NAME, OdfStylePropertiesSet.RubyProperties);
        mStylePropertiesElementToSetMap.put(StyleSectionPropertiesElement.ELEMENT_NAME, OdfStylePropertiesSet.SectionProperties);
        mStylePropertiesElementToSetMap.put(StyleTableCellPropertiesElement.ELEMENT_NAME, OdfStylePropertiesSet.TableCellProperties);
        mStylePropertiesElementToSetMap.put(StyleTableColumnPropertiesElement.ELEMENT_NAME, OdfStylePropertiesSet.TableColumnProperties);
        mStylePropertiesElementToSetMap.put(StyleTablePropertiesElement.ELEMENT_NAME, OdfStylePropertiesSet.TableProperties);
        mStylePropertiesElementToSetMap.put(StyleTableRowPropertiesElement.ELEMENT_NAME, OdfStylePropertiesSet.TableRowProperties);
        mStylePropertiesElementToSetMap.put(StyleTextPropertiesElement.ELEMENT_NAME, OdfStylePropertiesSet.TextProperties);
    }

    /** Creates a new instance of OdfElement */
    public OdfStyleBase(OdfFileDom ownerDocument,
            String namespaceURI,
            String qualifiedName) throws DOMException {
        super(ownerDocument, namespaceURI, qualifiedName);
    }

    /** Creates a new instance of OdfElement */
    public OdfStyleBase(OdfFileDom ownerDocument,
            OdfName aName) throws DOMException {
        super(ownerDocument, aName.getUri(), aName.getQName());
    }

    public void addStyleUser(OdfStylableElement user) {
        if (mStyleUser == null) {
            mStyleUser = new ArrayList<OdfStylableElement>();
        }
        mStyleUser.add(user);
    }

    /**
     * get a map containing all properties of this style and their values.
     * @return map of properties. 
     */
    public Map<OdfStyleProperty, String> getStyleProperties() {
        TreeMap<OdfStyleProperty, String> result = new TreeMap<OdfStyleProperty, String>();
        OdfStyleFamily family = getFamily();
        if (family != null) {
            for (OdfStyleProperty property : family.getProperties()) {
                if (hasProperty(property)) {
                    result.put(property, getProperty(property));
                }
            }
        }
        return result;
    }

    /**
     * get a map containing all properties of this style and their values.
     * The map will also include any properties set by parent styles
     * @return  a map of all the properties.
     */
    public Map<OdfStyleProperty, String> getStylePropertiesDeep() {
        TreeMap<OdfStyleProperty, String> result = new TreeMap<OdfStyleProperty, String>();
        OdfStyleBase style = this;
        while (style != null) {
            OdfStyleFamily family = style.getFamily();
            if (family != null) {
                for (OdfStyleProperty property : family.getProperties()) {
                    if (!result.containsKey(property) && style.hasProperty(property)) {
                        result.put(property, style.getProperty(property));
                    }
                }
            }

            style = style.getParentStyle();
        }
        return result;
    }

    public void removeStyleUser(OdfStylableElement user) {
        if (mStyleUser != null) {
            mStyleUser.remove(user);
        }
    }

    public int getStyleUserCount() {
        return mStyleUser == null ? 0 : mStyleUser.size();
    }

    /** Returns an iterator for all <code>OdfStylableElement</code> elements
     * using this style.
     *
     * @return an iterator for all <code>OdfStylableElement</code> elements
     * using this style
     */
    public Iterable<OdfStylableElement> getStyleUsers() {
        if (mStyleUser != null) {
            return mStyleUser;
        }
        return new ArrayList<OdfStylableElement>();
    }

    public String getFamilyName() {
        return getFamily().getName();
    }

    abstract public OdfStyleFamily getFamily();

    /**
     * 
     * @param set
     * @return the style:*-properties element for the given set. Returns null if
     *         such element does not exist yet.
     */
    public OdfStylePropertiesBase getPropertiesElement(OdfStylePropertiesSet set) {
        if (mPropertySetElementMap != null) {
            return mPropertySetElementMap.get(set);
        }

        return null;
    }

    /**
     * 
     * @param set
     * @return the style:*-properties element for the given set. If such element
     *         does not yet exist, it is created.
     */
    public OdfStylePropertiesBase getOrCreatePropertiesElement(OdfStylePropertiesSet set) {
        OdfStylePropertiesBase properties = null;

        if (mPropertySetElementMap != null) {
            properties = mPropertySetElementMap.get(set);
        }

        if (properties == null) {
            for (Entry<OdfName, OdfStylePropertiesSet> entry : mStylePropertiesElementToSetMap.entrySet()) {
                if (entry.getValue().equals(set)) {
                    properties = (OdfStylePropertiesBase) ((OdfFileDom) this.ownerDocument).createElementNS(entry.getKey());
                    if (getFirstChild() == null) {
                        appendChild(properties);
                    } else {
                        // make sure the properties elements are in the correct order
                        Node beforeNode = null;
                        if (set.equals(OdfStylePropertiesSet.GraphicProperties)) {
                            beforeNode = OdfElement.findFirstChildNode(OdfStyleParagraphProperties.class, this);
                            if (beforeNode == null) {
                                beforeNode = OdfElement.findFirstChildNode(OdfStyleTextProperties.class, this);
                            }
                        } else if (set.equals(OdfStylePropertiesSet.ParagraphProperties)) {
                            beforeNode = OdfElement.findFirstChildNode(OdfStyleTextProperties.class, this);
                        } else if (!set.equals(OdfStylePropertiesSet.TextProperties)) {
                            beforeNode = getFirstChild();
                        }

                        if (beforeNode == null) {
                            beforeNode = getFirstChild();
                            // find first non properties node
                            while (beforeNode != null) {
                                if (beforeNode.getNodeType() == Node.ELEMENT_NODE) {
                                    if (!(beforeNode instanceof OdfStylePropertiesBase)) {
                                        break;
                                    }
                                }
                                beforeNode = beforeNode.getNextSibling();
                            }
                        }

                        insertBefore(properties, beforeNode);
                    }
                    break;
                }
            }
        }

        return properties;
    }

    /**
     * 
     * @return a property value.
     */
    public String getProperty(OdfStyleProperty prop) {
        String value = null;

        OdfStylePropertiesBase properties = getPropertiesElement(prop.getPropertySet());
        if (properties != null) {
            if (properties.hasAttributeNS(prop.getName().getUri(), prop.getName().getLocalName())) {
                return properties.getOdfAttribute(prop.getName()).getValue();
            }
        }

        OdfStyleBase parent = getParentStyle();
        if (parent != null) {
            return parent.getProperty(prop);
        }

        return value;
    }

    public boolean hasProperty(OdfStyleProperty prop) {
        if (mPropertySetElementMap != null) {
            OdfStylePropertiesBase properties = mPropertySetElementMap.get(prop.getPropertySet());
            if (properties != null) {
                return properties.hasAttributeNS(prop.getName().getUri(), prop.getName().getLocalName());
            }
        }
        return false;
    }

    @Override
    protected void onOdfNodeInserted(OdfElement node, Node refChild) {
        if (node instanceof OdfStylePropertiesBase) {
            OdfStylePropertiesSet set = mStylePropertiesElementToSetMap.get(node.getOdfName());
            if (set != null) {
                if (mPropertySetElementMap == null) {
                    mPropertySetElementMap = new HashMap<OdfStylePropertiesSet, OdfStylePropertiesBase>();
                }
                mPropertySetElementMap.put(set, (OdfStylePropertiesBase) node);
            }
        }
    }

    @Override
    protected void onOdfNodeRemoved(OdfElement node) {
        if (mPropertySetElementMap != null) {
            if (node instanceof OdfStylePropertiesBase) {
                OdfStylePropertiesSet set = mStylePropertiesElementToSetMap.get(node.getOdfName());
                if (set != null) {
                    mPropertySetElementMap.remove(set);
                }
            }
        }
    }

    public Map<OdfStyleProperty, String> getProperties(Set<OdfStyleProperty> properties) {
        HashMap<OdfStyleProperty, String> map = new HashMap<OdfStyleProperty, String>();
        for (OdfStyleProperty property : properties) {
            map.put(property, getProperty(property));
        }

        return map;
    }

    public Set<OdfStyleProperty> getStrictProperties() {
        return getFamily().getProperties();
    }

    public void removeProperty(OdfStyleProperty property) {
        if (mPropertySetElementMap != null) {
            OdfStylePropertiesBase properties = mPropertySetElementMap.get(property.getPropertySet());
            if (properties != null) {
                properties.removeAttributeNS(property.getName().getUri(), property.getName().getLocalName());
            }
        }
    }

    public void setProperties(Map<OdfStyleProperty, String> properties) {
        for (Map.Entry<OdfStyleProperty, String> entry : properties.entrySet()) {
            setProperty(entry.getKey(), entry.getValue());
        }
    }

    public void setProperty(OdfStyleProperty property, String value) {
        OdfStylePropertiesBase properties = getOrCreatePropertiesElement(property.getPropertySet());
        if (properties != null) {
        	OdfAttribute propertyAttr = ((OdfFileDom) this.ownerDocument).createAttributeNS(property.getName());
            properties.setOdfAttribute(propertyAttr);
            propertyAttr.setValue(value);
        }
    }

    /** compare one style to another one.
     *  This implements a total order on style objects.
     *
     * @param obj - the reference object with which to compare2.
     * @return 0 if this object is the same as the obj argument; -1 if this
     * object is less than the obj argument; 1 if this object is greater than
     * the obj argument
     */
    public int compareTo(Object obj) {
        if (this == obj) {
            return 0;
        }

        if (!(obj instanceof OdfStyleBase)) {
            if (obj == null) {
                throw new ClassCastException("The object to be compared is null!");
            } else {
                throw new ClassCastException("The object to be compared is not a style!");
            }
        }
        OdfStyleBase compare = (OdfStyleBase) obj;

        int c = compareNodes(this, compare);
        return c;
    }

    // Currently this function does not consider the order of child nodes, e.g.,
    //
    //		<style:style style:name="P1" style:family="paragraph" style:parent-style-name="Standard">
    //			<style:paragraph-properties>
    //				<style:tab-stops>
    //					<style:tab-stop style:position="4.344cm"/>
    //				</style:tab-stops>
    //				<style:background-image xlink:href="Pictures/1.jpg" xlink:type="simple" xlink:actuate="onLoad"/>
    //			</style:paragraph-properties>
    //		</style:style>
    //
    //  and
    //
    //		<style:style style:name="P2" style:family="paragraph" style:parent-style-name="Standard">
    //			<style:paragraph-properties>
    //				<style:background-image xlink:href="Pictures/1.jpg" xlink:type="simple" xlink:actuate="onLoad"/>
    //				<style:tab-stops>
    //					<style:tab-stop style:position="4.344cm"/>
    //				</style:tab-stops>
    //			</style:paragraph-properties>
    //		</style:style>
    //
    //  are regarded non-equal
    //
    static private int compareNodes(Node compare1, Node compare2) {
        // Only styles can be equal, that are from the same element
        // (e.g. style:style and text:list-level-style-bullet are never equal)
        int c = 0;
        // if the local name is unequal (e.g. style vs. list-level-style-bullet)
        // the String compareTo will give me the order
        if ((c = compare1.getLocalName().compareTo(compare2.getLocalName())) != 0) {
            return c;
        }

        // if the namespaceURI is unequal (e.g. style vs. text)
        // the String compareTo will give me the order
        if ((c = compare1.getNamespaceURI().compareTo(compare2.getNamespaceURI())) != 0) {
            return c;
        }

        // compare number of attributes
        int attr_count1 = compare1.getAttributes() != null ? compare1.getAttributes().getLength() : 0;
        int attr_count2 = compare2.getAttributes() != null ? compare2.getAttributes().getLength() : 0;

        // attributes with default values do not exist in the ODFDOM XML model
        if (attr_count1 != attr_count2) {
            return attr_count1 < attr_count2 ? -1 : 1;
        }

        // sort attributes by namespace:localname, omit style name
        SortedMap<String, String> attr1 = getSortedAttributes(compare1);
        SortedMap<String, String> attr2 = getSortedAttributes(compare2);

        // compare2 attribute names and values
        Iterator<String> keySet1Iter = attr1.keySet().iterator();
        Iterator<String> keySet2Iter = attr2.keySet().iterator();

        while (keySet1Iter.hasNext()) {
            String key1 = keySet1Iter.next();
            String key2 = keySet2Iter.next();

            if ((c = key1.compareTo(key2)) != 0) {
                return c;
            }

            String attrValue1 = attr1.get(key1);
            String attrValue2 = attr2.get(key1);
            
            if ((c = attrValue1.compareTo(attrValue2)) != 0) {
                return c;
            }
        }

        // now number of child elements
        ArrayList<Node> nodes1 = getNonEmptyChildNodes(compare1);
        ArrayList<Node> nodes2 = getNonEmptyChildNodes(compare2);

        if (nodes1.size() != nodes2.size()) {
            return nodes1.size() < nodes2.size() ? -1 : 1;
        }

        // now compare child elements
        Iterator<Node> iter1 = nodes1.iterator();
        Iterator<Node> iter2 = nodes2.iterator();

        while (iter1.hasNext()) {
            Node child1 = iter1.next();
            Node child2 = iter2.next();
            if ((c = compareNodes(child1, child2)) != 0) {
                return c;
            }
        }

        return 0;
    }

    // helper function for compareTo.
    // sorts attributes by namespace:localname
    private static SortedMap<String, String> getSortedAttributes(Node node) {
        SortedMap<String, String> ret = new TreeMap<String, String>();
        NamedNodeMap attrs = node.getAttributes();
        for (int i = 0; i < attrs.getLength(); i++) {
            Node cur = attrs.item(i);
            String namespace = cur.getNamespaceURI();
            String local = cur.getLocalName();
            // styles can be still the same, even if they have different names
            if (local.equals("name") && namespace.equals(OdfNamespaceNames.STYLE.getNamespaceUri())) {
                continue;
            }
            ret.put(namespace + ":" + local, ((Attr) cur).getValue());
        }
        return ret;
    }

    // helper function for compareTo.
    // all except "empty" text nodes will be returned
    private static ArrayList<Node> getNonEmptyChildNodes(Node node) {
        ArrayList<Node> ret = new ArrayList<Node>();
        NodeList childs = node.getChildNodes();
        for (int i = 0; i < childs.getLength(); i++) {
            Node cur = childs.item(i);
            if (cur.getNodeType() == Node.TEXT_NODE) {
                if (cur.getNodeValue().trim().length() == 0) {
                    continue; // skip whitespace text nodes
                }
            }
            ret.add(cur);
        }
        return ret;
    }

    /** Indicates if some other object is equal to this one.
     *  The attribute style:name is ignored during compare2.
     *
     * @param obj - the reference object with which to compare2.
     * @return true if this object is the same as the obj argument; false otherwise.
     */
    @Override
    public boolean equals(Object obj) {
        return obj != null ? compareTo(obj) == 0 : false;
    }

    @Override
    public int hashCode() {
        return 59 * 7 + (this.mPropertySetElementMap != null ? this.mPropertySetElementMap.hashCode() : 0);
    }

    abstract public OdfStyleBase getParentStyle();
}
