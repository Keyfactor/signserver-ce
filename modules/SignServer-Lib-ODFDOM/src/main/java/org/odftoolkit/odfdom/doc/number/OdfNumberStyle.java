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

package org.odftoolkit.odfdom.doc.number;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.odftoolkit.odfdom.OdfFileDom;
import org.odftoolkit.odfdom.doc.style.OdfStyleMap;
import org.odftoolkit.odfdom.dom.element.number.NumberNumberStyleElement;

/**
 * Convenient functionalty for the parent ODF OpenDocument element
 *
 */
public class OdfNumberStyle extends NumberNumberStyleElement
{
	public OdfNumberStyle( OdfFileDom ownerDoc )
    {
        super( ownerDoc );
    }

	public OdfNumberStyle(OdfFileDom ownerDoc, String format, String styleName)
	{
		super(ownerDoc);
		this.setStyleNameAttribute(styleName);
		buildFromFormat(format);
}

	/**
	 * Creates a &lt;number:number-style&gt; element based upon format.
	 * @param format the number format string
	 */
	public void buildFromFormat(String format)
	{
		/*
		 * Setting ownerDoc won't be necessary once this is folded into
		 * OdfNumberStyle
		 */
		String preMatch;
		String numberSpec;
		String postMatch;
		int pos;
		char ch;
		int nDigits;

		Pattern p = Pattern.compile("[#0,.]+");
		Matcher m;
		OdfNumber number;

		/*
		 * If there is a numeric specifcation, then split the
		 * string into the part before the specifier, the specifier
		 * itself, and then part after the specifier. The parts
		 * before and after are just text (which may contain the
		 * currency symbol).
		 */
		if (format != null && !format.equals(""))
		{
			m = p.matcher(format);
			if (m.find())
			{
				preMatch = format.substring(0,m.start());
				numberSpec = format.substring(m.start(), m.end());
				postMatch = format.substring(m.end());

				emitText(preMatch);

				number = new OdfNumber((OdfFileDom) this.getOwnerDocument());

				/* Process part before the decimal point (if any) */
				nDigits = 0;
				for (pos = 0; pos < numberSpec.length() &&
					(ch = numberSpec.charAt(pos)) != '.'; pos++)
				{
					if (ch == ',')
					{
						number.setNumberGroupingAttribute(new Boolean(true));
					}
					else if (ch == '0')
					{
						nDigits++;
					}
				}
				number.setNumberMinIntegerDigitsAttribute(nDigits);

				/* Number of decimal places is the length after the decimal */
				if (pos < numberSpec.length())
				{
					number.setNumberDecimalPlacesAttribute(numberSpec.length() - (pos + 1));
				}
				this.appendChild(number);

				emitText(postMatch);
			}
		}
	}

	/**
	 *	Place pending text into a &lt;number:text&gt; element.
	 * @param textBuffer pending text
	 */
	private void emitText(String textBuffer)
	{
		OdfNumberText textElement;
		if (!textBuffer.equals(""))
		{
			textElement = new OdfNumberText((OdfFileDom) this.getOwnerDocument());
			textElement.setTextContent( textBuffer );
			this.appendChild( textElement );
		}
	}
	/**
	 * Set &lt;style:map&gt; for positive values to the given style name.
	 * @param mapName the style name to map to
	 */
	public void setMapPositive(String mapName)
	{
		OdfStyleMap map = new OdfStyleMap((OdfFileDom) this.getOwnerDocument());
		map.setStyleApplyStyleNameAttribute(mapName);
		map.setStyleConditionAttribute("value()>0");
		this.appendChild(map);
	}

	/**
	 * Set &lt;style:map&gt; for negative values to the given style name.
	 * @param mapName the style name to map to
	 */
	public void setMapNegative(String mapName)
	{
		OdfStyleMap map = new OdfStyleMap((OdfFileDom) this.getOwnerDocument());
		map.setStyleApplyStyleNameAttribute(mapName);
		map.setStyleConditionAttribute("value()<0");
		this.appendChild(map);
	}

}
