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

package org.odftoolkit.odfdom.dom.element.text;

import org.odftoolkit.odfdom.OdfName;
import org.odftoolkit.odfdom.OdfNamespace;
import org.odftoolkit.odfdom.OdfFileDom;
import org.odftoolkit.odfdom.dom.OdfNamespaceNames;
import org.odftoolkit.odfdom.dom.element.OdfStyleBase;
import org.odftoolkit.odfdom.dom.attribute.text.TextLevelAttribute;
import org.odftoolkit.odfdom.dom.attribute.text.TextStyleNameAttribute;
import org.odftoolkit.odfdom.dom.attribute.style.StyleNumFormatAttribute;
import org.odftoolkit.odfdom.dom.attribute.style.StyleNumLetterSyncAttribute;
import org.odftoolkit.odfdom.dom.attribute.style.StyleNumPrefixAttribute;
import org.odftoolkit.odfdom.dom.attribute.style.StyleNumSuffixAttribute;
import org.odftoolkit.odfdom.dom.attribute.text.TextDisplayLevelsAttribute;
import org.odftoolkit.odfdom.dom.attribute.text.TextStartValueAttribute;

import org.odftoolkit.odfdom.dom.element.style.StyleListLevelPropertiesElement;
import org.odftoolkit.odfdom.dom.element.style.StyleTextPropertiesElement;

/**
 * DOM implementation of OpenDocument element  {@odf.element text:outline-level-style}.
 *
 */
public abstract class TextOutlineLevelStyleElement extends OdfStyleBase
{        
    public static final OdfName ELEMENT_NAME = OdfName.get( OdfNamespace.get(OdfNamespaceNames.TEXT), "outline-level-style" );


	/**
	 * Create the instance of <code>TextOutlineLevelStyleElement</code> 
	 *
	 * @param  ownerDoc     The type is <code>OdfFileDom</code>
	 */
	public TextOutlineLevelStyleElement( OdfFileDom ownerDoc )
	{
		super( ownerDoc, ELEMENT_NAME	);
	}

	/**
	 * Get the element name 
	 *
	 * @return  return   <code>OdfName</code> the name of element {@odf.element text:outline-level-style}.
	 */
	public OdfName getOdfName()
	{
		return ELEMENT_NAME;
	}

	/**
	 * Initialization of the mandatory attributes of {@link  TextOutlineLevelStyleElement}
	 *
     * @param textLevelAttributeValue  The mandatory attribute {@odf.attribute  text:level}"
     * @param styleNumFormatAttributeValue  The mandatory attribute {@odf.attribute  style:num-format}"
     *
	 */
	public void init(int textLevelAttributeValue, String styleNumFormatAttributeValue)
	{
		setTextLevelAttribute( Integer.valueOf(textLevelAttributeValue) );
		setStyleNumFormatAttribute( styleNumFormatAttributeValue );
	}

	/**
	 * Receives the value of the ODFDOM attribute representation <code>TextLevelAttribute</code> , See {@odf.attribute text:level}
	 *
	 * @return - the <code>Integer</code> , the value or <code>null</code>, if the attribute is not set and no default value defined.
	 */
	public Integer getTextLevelAttribute()
	{
		TextLevelAttribute attr = (TextLevelAttribute) getOdfAttribute( OdfName.get( OdfNamespace.get(OdfNamespaceNames.TEXT), "level" ) );
		if( attr != null ){
			return Integer.valueOf( attr.intValue() );
		}
		return null;
	}
		 
	/**
	 * Sets the value of ODFDOM attribute representation <code>TextLevelAttribute</code> , See {@odf.attribute text:level}
	 *
	 * @param textLevelValue   The type is <code>Integer</code>
	 */
	public void setTextLevelAttribute( Integer textLevelValue )
	{
		TextLevelAttribute attr =  new TextLevelAttribute( (OdfFileDom)this.ownerDocument );
		setOdfAttribute( attr );
		attr.setIntValue( textLevelValue.intValue() );
	}


	/**
	 * Receives the value of the ODFDOM attribute representation <code>TextStyleNameAttribute</code> , See {@odf.attribute text:style-name}
	 *
	 * @return - the <code>String</code> , the value or <code>null</code>, if the attribute is not set and no default value defined.
	 */
	public String getTextStyleNameAttribute()
	{
		TextStyleNameAttribute attr = (TextStyleNameAttribute) getOdfAttribute( OdfName.get( OdfNamespace.get(OdfNamespaceNames.TEXT), "style-name" ) );
		if( attr != null ){
			return String.valueOf( attr.getValue() );
		}
		return null;
	}
		 
	/**
	 * Sets the value of ODFDOM attribute representation <code>TextStyleNameAttribute</code> , See {@odf.attribute text:style-name}
	 *
	 * @param textStyleNameValue   The type is <code>String</code>
	 */
	public void setTextStyleNameAttribute( String textStyleNameValue )
	{
		TextStyleNameAttribute attr =  new TextStyleNameAttribute( (OdfFileDom)this.ownerDocument );
		setOdfAttribute( attr );
		attr.setValue( textStyleNameValue );
	}


	/**
	 * Receives the value of the ODFDOM attribute representation <code>StyleNumFormatAttribute</code> , See {@odf.attribute style:num-format}
	 *
	 * @return - the <code>String</code> , the value or <code>null</code>, if the attribute is not set and no default value defined.
	 */
	public String getStyleNumFormatAttribute()
	{
		StyleNumFormatAttribute attr = (StyleNumFormatAttribute) getOdfAttribute( OdfName.get( OdfNamespace.get(OdfNamespaceNames.STYLE), "num-format" ) );
		if( attr != null ){
			return String.valueOf( attr.getValue() );
		}
		return null;
	}
		 
	/**
	 * Sets the value of ODFDOM attribute representation <code>StyleNumFormatAttribute</code> , See {@odf.attribute style:num-format}
	 *
	 * @param styleNumFormatValue   The type is <code>String</code>
	 */
	public void setStyleNumFormatAttribute( String styleNumFormatValue )
	{
		StyleNumFormatAttribute attr =  new StyleNumFormatAttribute( (OdfFileDom)this.ownerDocument );
		setOdfAttribute( attr );
		attr.setValue( styleNumFormatValue );
	}


	/**
	 * Receives the value of the ODFDOM attribute representation <code>StyleNumLetterSyncAttribute</code> , See {@odf.attribute style:num-letter-sync}
	 *
	 * @return - the <code>Boolean</code> , the value or <code>null</code>, if the attribute is not set and no default value defined.
	 */
	public Boolean getStyleNumLetterSyncAttribute()
	{
		StyleNumLetterSyncAttribute attr = (StyleNumLetterSyncAttribute) getOdfAttribute( OdfName.get( OdfNamespace.get(OdfNamespaceNames.STYLE), "num-letter-sync" ) );
		if( attr != null ){
			return Boolean.valueOf( attr.booleanValue() );
		}
		return null;
	}
		 
	/**
	 * Sets the value of ODFDOM attribute representation <code>StyleNumLetterSyncAttribute</code> , See {@odf.attribute style:num-letter-sync}
	 *
	 * @param styleNumLetterSyncValue   The type is <code>Boolean</code>
	 */
	public void setStyleNumLetterSyncAttribute( Boolean styleNumLetterSyncValue )
	{
		StyleNumLetterSyncAttribute attr =  new StyleNumLetterSyncAttribute( (OdfFileDom)this.ownerDocument );
		setOdfAttribute( attr );
		attr.setBooleanValue( styleNumLetterSyncValue.booleanValue() );
	}


	/**
	 * Receives the value of the ODFDOM attribute representation <code>StyleNumPrefixAttribute</code> , See {@odf.attribute style:num-prefix}
	 *
	 * @return - the <code>String</code> , the value or <code>null</code>, if the attribute is not set and no default value defined.
	 */
	public String getStyleNumPrefixAttribute()
	{
		StyleNumPrefixAttribute attr = (StyleNumPrefixAttribute) getOdfAttribute( OdfName.get( OdfNamespace.get(OdfNamespaceNames.STYLE), "num-prefix" ) );
		if( attr != null ){
			return String.valueOf( attr.getValue() );
		}
		return null;
	}
		 
	/**
	 * Sets the value of ODFDOM attribute representation <code>StyleNumPrefixAttribute</code> , See {@odf.attribute style:num-prefix}
	 *
	 * @param styleNumPrefixValue   The type is <code>String</code>
	 */
	public void setStyleNumPrefixAttribute( String styleNumPrefixValue )
	{
		StyleNumPrefixAttribute attr =  new StyleNumPrefixAttribute( (OdfFileDom)this.ownerDocument );
		setOdfAttribute( attr );
		attr.setValue( styleNumPrefixValue );
	}


	/**
	 * Receives the value of the ODFDOM attribute representation <code>StyleNumSuffixAttribute</code> , See {@odf.attribute style:num-suffix}
	 *
	 * @return - the <code>String</code> , the value or <code>null</code>, if the attribute is not set and no default value defined.
	 */
	public String getStyleNumSuffixAttribute()
	{
		StyleNumSuffixAttribute attr = (StyleNumSuffixAttribute) getOdfAttribute( OdfName.get( OdfNamespace.get(OdfNamespaceNames.STYLE), "num-suffix" ) );
		if( attr != null ){
			return String.valueOf( attr.getValue() );
		}
		return null;
	}
		 
	/**
	 * Sets the value of ODFDOM attribute representation <code>StyleNumSuffixAttribute</code> , See {@odf.attribute style:num-suffix}
	 *
	 * @param styleNumSuffixValue   The type is <code>String</code>
	 */
	public void setStyleNumSuffixAttribute( String styleNumSuffixValue )
	{
		StyleNumSuffixAttribute attr =  new StyleNumSuffixAttribute( (OdfFileDom)this.ownerDocument );
		setOdfAttribute( attr );
		attr.setValue( styleNumSuffixValue );
	}


	/**
	 * Receives the value of the ODFDOM attribute representation <code>TextDisplayLevelsAttribute</code> , See {@odf.attribute text:display-levels}
	 *
	 * @return - the <code>Integer</code> , the value or <code>null</code>, if the attribute is not set and no default value defined.
	 */
	public Integer getTextDisplayLevelsAttribute()
	{
		TextDisplayLevelsAttribute attr = (TextDisplayLevelsAttribute) getOdfAttribute( OdfName.get( OdfNamespace.get(OdfNamespaceNames.TEXT), "display-levels" ) );
		if( attr != null ){
			return Integer.valueOf( attr.intValue() );
		}
		return Integer.valueOf( TextDisplayLevelsAttribute.DEFAULT_VALUE );
	}
		 
	/**
	 * Sets the value of ODFDOM attribute representation <code>TextDisplayLevelsAttribute</code> , See {@odf.attribute text:display-levels}
	 *
	 * @param textDisplayLevelsValue   The type is <code>Integer</code>
	 */
	public void setTextDisplayLevelsAttribute( Integer textDisplayLevelsValue )
	{
		TextDisplayLevelsAttribute attr =  new TextDisplayLevelsAttribute( (OdfFileDom)this.ownerDocument );
		setOdfAttribute( attr );
		attr.setIntValue( textDisplayLevelsValue.intValue() );
	}


	/**
	 * Receives the value of the ODFDOM attribute representation <code>TextStartValueAttribute</code> , See {@odf.attribute text:start-value}
	 *
	 * @return - the <code>String</code> , the value or <code>null</code>, if the attribute is not set and no default value defined.
	 */
	public String getTextStartValueAttribute()
	{
		TextStartValueAttribute attr = (TextStartValueAttribute) getOdfAttribute( OdfName.get( OdfNamespace.get(OdfNamespaceNames.TEXT), "start-value" ) );
		if( attr != null ){
			return String.valueOf( attr.getValue() );
		}
		return TextStartValueAttribute.DEFAULT_VALUE;
	}
		 
	/**
	 * Sets the value of ODFDOM attribute representation <code>TextStartValueAttribute</code> , See {@odf.attribute text:start-value}
	 *
	 * @param textStartValueValue   The type is <code>String</code>
	 */
	public void setTextStartValueAttribute( String textStartValueValue )
	{
		TextStartValueAttribute attr =  new TextStartValueAttribute( (OdfFileDom)this.ownerDocument );
		setOdfAttribute( attr );
		attr.setValue( textStartValueValue );
	}

	/**
	 * Create child element {@odf.element style:list-level-properties}.
	 *
	 * @return   return  the element {@odf.element style:list-level-properties}
	 * DifferentQName 
	 */
	public StyleListLevelPropertiesElement newStyleListLevelPropertiesElement()
	{
		StyleListLevelPropertiesElement  styleListLevelProperties = ((OdfFileDom)this.ownerDocument).newOdfElement(StyleListLevelPropertiesElement.class);
		this.appendChild( styleListLevelProperties);
		return  styleListLevelProperties;
	}                   
               
	/**
	 * Create child element {@odf.element style:text-properties}.
	 *
     * @param textDisplayAttributeValue  the <code>String</code> value of <code>TextDisplayAttribute</code>, see {@odf.attribute  text:display} at specification
	 * @return   return  the element {@odf.element style:text-properties}
	 * DifferentQName 
	 */
    
	public StyleTextPropertiesElement newStyleTextPropertiesElement(String textDisplayAttributeValue)
	{
		StyleTextPropertiesElement  styleTextProperties = ((OdfFileDom)this.ownerDocument).newOdfElement(StyleTextPropertiesElement.class);
		styleTextProperties.setTextDisplayAttribute( textDisplayAttributeValue );
		this.appendChild( styleTextProperties);
		return  styleTextProperties;      
	}
    
	/**
	 * Create child element {@odf.element style:text-properties}.
	 *
     * @param textConditionAttributeValue  the <code>String</code> value of <code>TextConditionAttribute</code>, see {@odf.attribute  text:condition} at specification
	 * @param textDisplayAttributeValue  the <code>String</code> value of <code>TextDisplayAttribute</code>, see {@odf.attribute  text:display} at specification
	 * @return   return  the element {@odf.element style:text-properties}
	 * DifferentQName 
	 */
    
	public StyleTextPropertiesElement newStyleTextPropertiesElement(String textConditionAttributeValue, String textDisplayAttributeValue)
	{
		StyleTextPropertiesElement  styleTextProperties = ((OdfFileDom)this.ownerDocument).newOdfElement(StyleTextPropertiesElement.class);
		styleTextProperties.setTextConditionAttribute( textConditionAttributeValue );
		styleTextProperties.setTextDisplayAttribute( textDisplayAttributeValue );
		this.appendChild( styleTextProperties);
		return  styleTextProperties;      
	}
    
}
