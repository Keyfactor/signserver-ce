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

/*
 * This file is automatically generated.
 * Don't edit manually.
 */    

package org.odftoolkit.odfdom.dom.element.draw;

import org.odftoolkit.odfdom.OdfName;
import org.odftoolkit.odfdom.OdfNamespace;
import org.odftoolkit.odfdom.OdfFileDom;
import org.odftoolkit.odfdom.dom.OdfNamespaceNames;
import org.odftoolkit.odfdom.OdfElement;
import org.odftoolkit.odfdom.dom.attribute.draw.DrawRecreateOnEditAttribute;
import org.odftoolkit.odfdom.dom.attribute.svg.SvgWidthAttribute;
import org.odftoolkit.odfdom.dom.attribute.svg.SvgHeightAttribute;
import org.odftoolkit.odfdom.dom.attribute.svg.SvgViewBoxAttribute;
import org.odftoolkit.odfdom.dom.attribute.svg.SvgDAttribute;


/**
 * DOM implementation of OpenDocument element  {@odf.element draw:contour-path}.
 *
 */
public abstract class DrawContourPathElement extends OdfElement
{        
    public static final OdfName ELEMENT_NAME = OdfName.get( OdfNamespace.get(OdfNamespaceNames.DRAW), "contour-path" );


	/**
	 * Create the instance of <code>DrawContourPathElement</code> 
	 *
	 * @param  ownerDoc     The type is <code>OdfFileDom</code>
	 */
	public DrawContourPathElement( OdfFileDom ownerDoc )
	{
		super( ownerDoc, ELEMENT_NAME	);
	}

	/**
	 * Get the element name 
	 *
	 * @return  return   <code>OdfName</code> the name of element {@odf.element draw:contour-path}.
	 */
	public OdfName getOdfName()
	{
		return ELEMENT_NAME;
	}

	/**
	 * Initialization of the mandatory attributes of {@link  DrawContourPathElement}
	 *
     * @param drawRecreateOnEditAttributeValue  The mandatory attribute {@odf.attribute  draw:recreate-on-edit}"
     * @param svgViewBoxAttributeValue  The mandatory attribute {@odf.attribute  svg:viewBox}"
     * @param svgDAttributeValue  The mandatory attribute {@odf.attribute  svg:d}"
     *
	 */
	public void init(boolean drawRecreateOnEditAttributeValue, String svgViewBoxAttributeValue, String svgDAttributeValue)
	{
		setDrawRecreateOnEditAttribute( Boolean.valueOf(drawRecreateOnEditAttributeValue) );
		setSvgViewBoxAttribute( svgViewBoxAttributeValue );
		setSvgDAttribute( svgDAttributeValue );
	}

	/**
	 * Receives the value of the ODFDOM attribute representation <code>DrawRecreateOnEditAttribute</code> , See {@odf.attribute draw:recreate-on-edit}
	 *
	 * @return - the <code>Boolean</code> , the value or <code>null</code>, if the attribute is not set and no default value defined.
	 */
	public Boolean getDrawRecreateOnEditAttribute()
	{
		DrawRecreateOnEditAttribute attr = (DrawRecreateOnEditAttribute) getOdfAttribute( OdfName.get( OdfNamespace.get(OdfNamespaceNames.DRAW), "recreate-on-edit" ) );
		if( attr != null ){
			return Boolean.valueOf( attr.booleanValue() );
		}
		return null;
	}
		 
	/**
	 * Sets the value of ODFDOM attribute representation <code>DrawRecreateOnEditAttribute</code> , See {@odf.attribute draw:recreate-on-edit}
	 *
	 * @param drawRecreateOnEditValue   The type is <code>Boolean</code>
	 */
	public void setDrawRecreateOnEditAttribute( Boolean drawRecreateOnEditValue )
	{
		DrawRecreateOnEditAttribute attr =  new DrawRecreateOnEditAttribute( (OdfFileDom)this.ownerDocument );
		setOdfAttribute( attr );
		attr.setBooleanValue( drawRecreateOnEditValue.booleanValue() );
	}


	/**
	 * Receives the value of the ODFDOM attribute representation <code>SvgWidthAttribute</code> , See {@odf.attribute svg:width}
	 *
	 * @return - the <code>String</code> , the value or <code>null</code>, if the attribute is not set and no default value defined.
	 */
	public String getSvgWidthAttribute()
	{
		SvgWidthAttribute attr = (SvgWidthAttribute) getOdfAttribute( OdfName.get( OdfNamespace.get(OdfNamespaceNames.SVG), "width" ) );
		if( attr != null ){
			return String.valueOf( attr.getValue() );
		}
		return null;
	}
		 
	/**
	 * Sets the value of ODFDOM attribute representation <code>SvgWidthAttribute</code> , See {@odf.attribute svg:width}
	 *
	 * @param svgWidthValue   The type is <code>String</code>
	 */
	public void setSvgWidthAttribute( String svgWidthValue )
	{
		SvgWidthAttribute attr =  new SvgWidthAttribute( (OdfFileDom)this.ownerDocument );
		setOdfAttribute( attr );
		attr.setValue( svgWidthValue );
	}


	/**
	 * Receives the value of the ODFDOM attribute representation <code>SvgHeightAttribute</code> , See {@odf.attribute svg:height}
	 *
	 * @return - the <code>String</code> , the value or <code>null</code>, if the attribute is not set and no default value defined.
	 */
	public String getSvgHeightAttribute()
	{
		SvgHeightAttribute attr = (SvgHeightAttribute) getOdfAttribute( OdfName.get( OdfNamespace.get(OdfNamespaceNames.SVG), "height" ) );
		if( attr != null ){
			return String.valueOf( attr.getValue() );
		}
		return null;
	}
		 
	/**
	 * Sets the value of ODFDOM attribute representation <code>SvgHeightAttribute</code> , See {@odf.attribute svg:height}
	 *
	 * @param svgHeightValue   The type is <code>String</code>
	 */
	public void setSvgHeightAttribute( String svgHeightValue )
	{
		SvgHeightAttribute attr =  new SvgHeightAttribute( (OdfFileDom)this.ownerDocument );
		setOdfAttribute( attr );
		attr.setValue( svgHeightValue );
	}


	/**
	 * Receives the value of the ODFDOM attribute representation <code>SvgViewBoxAttribute</code> , See {@odf.attribute svg:viewBox}
	 *
	 * @return - the <code>String</code> , the value or <code>null</code>, if the attribute is not set and no default value defined.
	 */
	public String getSvgViewBoxAttribute()
	{
		SvgViewBoxAttribute attr = (SvgViewBoxAttribute) getOdfAttribute( OdfName.get( OdfNamespace.get(OdfNamespaceNames.SVG), "viewBox" ) );
		if( attr != null ){
			return String.valueOf( attr.getValue() );
		}
		return null;
	}
		 
	/**
	 * Sets the value of ODFDOM attribute representation <code>SvgViewBoxAttribute</code> , See {@odf.attribute svg:viewBox}
	 *
	 * @param svgViewBoxValue   The type is <code>String</code>
	 */
	public void setSvgViewBoxAttribute( String svgViewBoxValue )
	{
		SvgViewBoxAttribute attr =  new SvgViewBoxAttribute( (OdfFileDom)this.ownerDocument );
		setOdfAttribute( attr );
		attr.setValue( svgViewBoxValue );
	}


	/**
	 * Receives the value of the ODFDOM attribute representation <code>SvgDAttribute</code> , See {@odf.attribute svg:d}
	 *
	 * @return - the <code>String</code> , the value or <code>null</code>, if the attribute is not set and no default value defined.
	 */
	public String getSvgDAttribute()
	{
		SvgDAttribute attr = (SvgDAttribute) getOdfAttribute( OdfName.get( OdfNamespace.get(OdfNamespaceNames.SVG), "d" ) );
		if( attr != null ){
			return String.valueOf( attr.getValue() );
		}
		return null;
	}
		 
	/**
	 * Sets the value of ODFDOM attribute representation <code>SvgDAttribute</code> , See {@odf.attribute svg:d}
	 *
	 * @param svgDValue   The type is <code>String</code>
	 */
	public void setSvgDAttribute( String svgDValue )
	{
		SvgDAttribute attr =  new SvgDAttribute( (OdfFileDom)this.ownerDocument );
		setOdfAttribute( attr );
		attr.setValue( svgDValue );
	}

}
