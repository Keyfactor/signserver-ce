/************************************************************************
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER
 *
 * Copyright 2008 Sun Microsystems, Inc. All rights reserved.
 * Copyright 2009 IBM. All rights reserved.
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
package org.odftoolkit.odfdom.doc.office;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.odftoolkit.odfdom.OdfElement;
import org.odftoolkit.odfdom.OdfFileDom;
import org.odftoolkit.odfdom.OdfNamespace;
import org.odftoolkit.odfdom.doc.draw.OdfDrawFrame;
import org.odftoolkit.odfdom.doc.draw.OdfDrawObject;
import org.odftoolkit.odfdom.doc.draw.OdfDrawPage;
import org.odftoolkit.odfdom.doc.draw.OdfDrawPageThumbnail;
import org.odftoolkit.odfdom.doc.presentation.OdfPresentationNotes;
import org.odftoolkit.odfdom.doc.style.OdfStylePresentationPageLayout;
import org.odftoolkit.odfdom.dom.OdfNamespaceNames;
import org.odftoolkit.odfdom.dom.attribute.presentation.PresentationClassAttribute;
import org.odftoolkit.odfdom.dom.element.office.OfficePresentationElement;
import org.odftoolkit.odfdom.dom.element.style.StyleDrawingPagePropertiesElement;
import org.odftoolkit.odfdom.dom.element.style.StyleGraphicPropertiesElement;
import org.odftoolkit.odfdom.pkg.OdfPackage;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Convenient functionality for the parent ODF OpenDocument element
 *
 */
public class OdfOfficePresentation extends OfficePresentationElement {

	private Logger mLog = Logger.getLogger(OdfPackage.class.getName());
	private ArrayList<OdfDrawPage> mPages;

	/**
	 * Constructor for creating an instance of presentation.
	 * @param ownerDoc  The XML DOM
	 */
	public OdfOfficePresentation(OdfFileDom ownerDoc) {
		super(ownerDoc);
	}

	/**
	 * Return a page at a specified position in this presentation.
	 *
	 * @param index  the index of the page to return
	 * @return       a draw page
	 */
	public OdfDrawPage getPageAt(int index) {
		if ((mPages != null) || (mPages.size() <= index)) {
			return mPages.get(index);
		} else {
			return null;
		}
	}

	/**
	 * Get the number of the pages in this presentation.
	 *
	 * @return    the number of pages
	 */
	public int getPageCount() {
		if (mPages != null) {
			return mPages.size();
		} else {
			return 0;
		}
	}

	/**
	 * Return a page with a specified page name in this presentation.
	 *
	 * @param name  the name of the page to return
	 * @return the page
	 */
	public OdfDrawPage getPage(String name) {
		if (mPages != null) {
			Iterator<OdfDrawPage> iter = mPages.iterator();
			while (iter.hasNext()) {
				OdfDrawPage page = iter.next();
				if (page.getDrawNameAttribute().equals(name)) {
					return page;
				}
			}
		}
		return null;
	}

	/**
	 * Return a list iterator containing all pages in this presentation.
	 *
	 * @return   a list iterator containing all pages in this presentation
	 */
	public Iterator<OdfDrawPage> getPages() {
		if (mPages != null) {
			return mPages.iterator();
		} else {
			return new ArrayList<OdfDrawPage>().iterator();
		}
	}

	/**
	 * Override this method to get notified about element insertion.
	 */
	protected void onOdfNodeInserted(OdfElement node, Node refNode) {
		if (node instanceof OdfDrawPage) {
			OdfDrawPage page = (OdfDrawPage) node;

			if (mPages == null) {
				mPages = new ArrayList<OdfDrawPage>();
			} else if (refNode != null) {
				int index = -1;
				OdfDrawPage refPage = findPreviousChildNode(OdfDrawPage.class, node);
				if (refPage != null) {
					index = mPages.indexOf(refPage);
				}
				mPages.add(index + 1, page);
				return;
			}
			mPages.add(page);
		}
	}

	/**
	 * Override this method to get notified about element insertion.
	 */
	protected void onOdfNodeRemoved(OdfElement node) {
		if (node instanceof OdfDrawPage) {
			if (mPages != null) {
				OdfDrawPage page = (OdfDrawPage) node;
				mPages.remove(page);
			}
		}
	}

	/**
	 * Delete a page at a specified position in this presentation.
	 *
	 * @param index  the index of the page to delete
	 */
	public void deletePage(int index) {

		NodeList pages = this.getElementsByTagNameNS(OdfNamespace.get(OdfNamespaceNames.DRAW).toString(), "page");
		try {
			NodeList objects = ((OdfDrawPage) pages.item(index)).getElementsByTagNameNS(OdfNamespace.get(OdfNamespaceNames.DRAW).toString(), "object");
			for (int j = 0; j < objects.getLength(); j++) {
				OdfDrawObject object = (OdfDrawObject) objects.item(j);
				mOdfDocument.RemoveEmbedDocument(object.getXlinkHrefAttribute().toString().substring(2));
			}
			this.removeChild(pages.item(index));
		} catch (Exception ex) {
			mLog.log(Level.SEVERE, null, ex);
		}

	}

	/**
	 * Delete a page with a specified name in this presentation
	 *
	 * @param name  the name of the page to delete
	 */
	public void deletePage(String name) {
		NodeList pages = this.getElementsByTagNameNS(OdfNamespace.get(OdfNamespaceNames.DRAW).toString(), "page");
		for (int i = 0; i < pages.getLength(); i++) {
			OdfDrawPage page = (OdfDrawPage) pages.item(i);
			if (page.getDrawNameAttribute().equals(name)) {
				NodeList objects = page.getElementsByTagNameNS(OdfNamespace.get(OdfNamespaceNames.DRAW).toString(), "object");
				for (int j = 0; j < objects.getLength(); j++) {
					OdfDrawObject object = (OdfDrawObject) objects.item(j);
					mOdfDocument.RemoveEmbedDocument(object.getXlinkHrefAttribute().toString().trim().substring(2));
				}
				this.removeChild(pages.item(i));
			}
		}
	}

	/**
	 * Insert the page after a specified position in this presentation.
	 *
	 * @param index    the position to insert after
	 * @param page     the page to be inserted
	 */
	public void insertPageAfter(int index, OdfDrawPage page) {
		NodeList pages = this.getElementsByTagNameNS(OdfNamespace.get(OdfNamespaceNames.DRAW).toString(), "page");
		try {
			this.insertBefore(page, pages.item(index + 1));
		} catch (Exception ex) {
			mLog.log(Level.SEVERE, null, ex);
		}

	}

	/**
	 * Insert the page before a specified position in this presentation.
	 *
	 * @param index   the position to insert before
	 * @param page    the page to be inserted
	 */
	public void insertPageBefore(int index, OdfDrawPage page) {

		NodeList pages = this.getElementsByTagNameNS(OdfNamespace.get(OdfNamespaceNames.DRAW).toString(), "page");
		try {
			this.insertBefore(page, pages.item(index));
		} catch (Exception ex) {
			mLog.log(Level.SEVERE, null, ex);
		}
	}

	/**
	 * Move a page at a specified position to the destination position.
	 *
	 * @param current       the current index of the page to be moved
	 * @param destination   The index of the destination position
	 */
	public void movePage(int current, int destination) {

		NodeList pages = this.getElementsByTagNameNS(OdfNamespace.get(OdfNamespaceNames.DRAW).toString(), "page");
		try {
			OdfDrawPage page = (OdfDrawPage) pages.item(current);
			this.insertBefore(page, pages.item(destination));
		} catch (Exception ex) {
			mLog.log(Level.SEVERE, null, ex);
		}

	}

	/**
	 * Create a page based on page template.
	 * A page template is a page with some predefine elements.
	 *
	 * @param pageType   the template type of the page to be created
	 * @param name       the name of page
	 * @return a page    the created page
	 * @see TemplatePageType
	 */
	public OdfDrawPage createTemplatePage(TemplatePageType pageType, String name) {
		OdfDrawPage page = (OdfDrawPage) this.newDrawPageElement("Default");
		this.insertPageBefore(0, page);
		page.setDrawNameAttribute(name);

		page.setProperty(StyleDrawingPagePropertiesElement.BackgroundVisible, "true");
		page.setProperty(StyleDrawingPagePropertiesElement.BackgroundObjectsVisible, "true");
		page.setProperty(StyleDrawingPagePropertiesElement.DisplayFooter, "true");
		page.setProperty(StyleDrawingPagePropertiesElement.DisplayPageNumber, "false");
		page.setProperty(StyleDrawingPagePropertiesElement.DisplayDateTime, "true");

		OdfOfficeStyles styles;
		String layoutName;

		if (pageType.toString().equals(TemplatePageType.ONLYTITLE.toString())) {
			layoutName = createUniqueLayoutName();
			try {
				styles = mOdfDocument.getStylesDom().getOfficeStyles();
				if (styles == null) {
					styles = mOdfDocument.getStylesDom().newOdfElement(OdfOfficeStyles.class);
				}
				OdfStylePresentationPageLayout layout = (OdfStylePresentationPageLayout) styles.newStylePresentationPageLayoutElement(layoutName);
				layout.newPresentationPlaceholderElement("title", "2.058cm", "1.743cm", "23.91cm", "3.507cm");
			} catch (Exception e1) {

				e1.printStackTrace();
			}
			page.setPresentationPresentationPageLayoutNameAttribute(layoutName);


			OdfDrawFrame frame1 = (OdfDrawFrame) page.newDrawFrameElement();
			frame1.setProperty(StyleGraphicPropertiesElement.Shadow, "true");
			frame1.setProperty(StyleGraphicPropertiesElement.AutoGrowHeight, "true");
			frame1.setProperty(StyleGraphicPropertiesElement.MinHeight, "3.507");
			frame1.setPresentationStyleNameAttribute(frame1.getStyleName());

			frame1.setDrawLayerAttribute("layout");
			frame1.setSvgHeightAttribute("3.006cm");
			frame1.setSvgWidthAttribute("24.299cm");
			frame1.setSvgXAttribute("1.35cm");
			frame1.setSvgYAttribute("0.717cm");
			frame1.setPresentationClassAttribute(PresentationClassAttribute.Value.TITLE.toString());
			frame1.setPresentationPlaceholderAttribute(new Boolean(true));
			frame1.newDrawTextBoxElement();
		} else if (pageType.toString().equals(TemplatePageType.OUTLINE.toString())) {
			layoutName = createUniqueLayoutName();
			try {
				styles = mOdfDocument.getStylesDom().getOfficeStyles();
				if (styles == null) {
					styles = mOdfDocument.getStylesDom().newOdfElement(OdfOfficeStyles.class);
				}
				OdfStylePresentationPageLayout layout = (OdfStylePresentationPageLayout) styles.newStylePresentationPageLayoutElement(layoutName);
				layout.newPresentationPlaceholderElement("title", "2.058cm", "1.743cm", "23.91cm", "3.507cm");
				layout.newPresentationPlaceholderElement("outline", "2.058cm", "1.743cm", "23.91cm", "3.507cm");

			} catch (Exception e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			page.setPresentationPresentationPageLayoutNameAttribute(layoutName);


			OdfDrawFrame frame1 = (OdfDrawFrame) page.newDrawFrameElement();
			frame1.setProperty(StyleGraphicPropertiesElement.Shadow, "true");
			frame1.setProperty(StyleGraphicPropertiesElement.AutoGrowHeight, "true");
			frame1.setProperty(StyleGraphicPropertiesElement.MinHeight, "3.507");
			frame1.setPresentationStyleNameAttribute(frame1.getStyleName());

			frame1.setDrawLayerAttribute("layout");
			frame1.setSvgHeightAttribute("3.006cm");
			frame1.setSvgWidthAttribute("24.299cm");
			frame1.setSvgXAttribute("1.35cm");
			frame1.setSvgYAttribute("0.717cm");
			frame1.setPresentationClassAttribute(PresentationClassAttribute.Value.TITLE.toString());
			frame1.setPresentationPlaceholderAttribute(new Boolean(true));
			frame1.newDrawTextBoxElement();
			OdfDrawFrame frame2 = (OdfDrawFrame) page.newDrawFrameElement();

			frame2.setProperty(StyleGraphicPropertiesElement.FillColor, "#ffffff");
			frame2.setProperty(StyleGraphicPropertiesElement.MinHeight, "13.114");
			frame2.setPresentationStyleNameAttribute(frame2.getStyleName());

			frame2.setDrawLayerAttribute("layout");
			frame2.setSvgHeightAttribute("11.629cm");
			frame2.setSvgWidthAttribute("24.199cm");
			frame2.setSvgXAttribute("1.35cm");
			frame2.setSvgYAttribute("4.337cm");
			frame2.setPresentationClassAttribute(PresentationClassAttribute.Value.SUBTITLE.toString());
			frame2.setPresentationPlaceholderAttribute(new Boolean(true));
			frame2.newDrawTextBoxElement();
		} else if (pageType.toString().equals(TemplatePageType.TEXT.toString())) {
			layoutName = createUniqueLayoutName();
			try {
				styles = mOdfDocument.getStylesDom().getOfficeStyles();
				if (styles == null) {
					styles = mOdfDocument.getStylesDom().newOdfElement(OdfOfficeStyles.class);
				}
				OdfStylePresentationPageLayout layout = (OdfStylePresentationPageLayout) styles.newStylePresentationPageLayoutElement(layoutName);
				layout.newPresentationPlaceholderElement("title", "2.058cm", "1.743cm", "23.91cm", "1.743cm");
				layout.newPresentationPlaceholderElement("subtitle", "2.058cm", "5.838cm", "23.91cm", "13.23cm");

			} catch (Exception e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			page.setPresentationPresentationPageLayoutNameAttribute(layoutName);

			OdfDrawFrame frame1 = (OdfDrawFrame) page.newDrawFrameElement();
			frame1.setProperty(StyleGraphicPropertiesElement.AutoGrowHeight, "true");
			frame1.setProperty(StyleGraphicPropertiesElement.MinHeight, "3.507");
			frame1.setPresentationStyleNameAttribute(frame1.getStyleName());

			frame1.setDrawLayerAttribute("layout");
			frame1.setSvgHeightAttribute("3.006cm");
			frame1.setSvgWidthAttribute("24.299cm");
			frame1.setSvgXAttribute("1.35cm");
			frame1.setSvgYAttribute("0.717cm");
			frame1.setPresentationClassAttribute(PresentationClassAttribute.Value.TITLE.toString());
			frame1.setPresentationPlaceholderAttribute(new Boolean(true));
			frame1.newDrawTextBoxElement();
			OdfDrawFrame frame2 = (OdfDrawFrame) page.newDrawFrameElement();
			frame2.setProperty(StyleGraphicPropertiesElement.AutoGrowHeight, "true");
			frame2.setProperty(StyleGraphicPropertiesElement.MinHeight, "3.507");
			frame2.setPresentationStyleNameAttribute(frame2.getStyleName());

			frame2.setDrawLayerAttribute("layout");
			frame2.setSvgHeightAttribute("11.88cm");
			frame2.setSvgWidthAttribute("24.299cm");
			frame2.setSvgXAttribute("1.35cm");
			frame2.setSvgYAttribute("4.212cm");
			frame2.setPresentationClassAttribute(PresentationClassAttribute.Value.OUTLINE.toString());
			frame2.setPresentationPlaceholderAttribute(new Boolean(true));
			frame2.newDrawTextBoxElement();

		} else if (pageType.toString().equals(TemplatePageType.TWOBLOCK.toString())) {

			layoutName = createUniqueLayoutName();
			try {
				styles = mOdfDocument.getStylesDom().getOfficeStyles();
				if (styles == null) {
					styles = mOdfDocument.getStylesDom().newOdfElement(OdfOfficeStyles.class);
				}
				OdfStylePresentationPageLayout layout = (OdfStylePresentationPageLayout) styles.newStylePresentationPageLayoutElement(layoutName);
				layout.newPresentationPlaceholderElement("outline", "2.058cm", "1.743cm", "23.91cm", "1.743cm");
				layout.newPresentationPlaceholderElement("outline", "1.35cm", "4.212cm", "11.857cm", "11.629cm");
				layout.newPresentationPlaceholderElement("outline", "4.212cm", "13.8cm", "11.857cm", "11.629cm");

			} catch (Exception e1) {

				e1.printStackTrace();
			}


			OdfDrawFrame frame1 = (OdfDrawFrame) page.newDrawFrameElement();
			frame1.setProperty(StyleGraphicPropertiesElement.AutoGrowHeight, "true");
			frame1.setProperty(StyleGraphicPropertiesElement.MinHeight, "3.507");
			frame1.setPresentationStyleNameAttribute(frame1.getStyleName());

			frame1.setDrawLayerAttribute("layout");
			frame1.setSvgHeightAttribute("3.006cm");
			frame1.setSvgWidthAttribute("24.299cm");
			frame1.setSvgXAttribute("1.35cm");
			frame1.setSvgYAttribute("0.717cm");
			frame1.setPresentationClassAttribute(PresentationClassAttribute.Value.TITLE.toString());
			frame1.setPresentationPlaceholderAttribute(new Boolean(true));
			frame1.newDrawTextBoxElement();
			OdfDrawFrame frame2 = (OdfDrawFrame) page.newDrawFrameElement();
			frame2.setProperty(StyleGraphicPropertiesElement.AutoGrowHeight, "true");
			frame2.setProperty(StyleGraphicPropertiesElement.MinHeight, "3.507");
			frame2.setPresentationStyleNameAttribute(frame2.getStyleName());

			frame2.setDrawLayerAttribute("layout");
			frame2.setSvgHeightAttribute("11.629cm");
			frame2.setSvgWidthAttribute("11.857cm");
			frame2.setSvgXAttribute("1.35cm");
			frame2.setSvgYAttribute("4.212cm");
			frame2.setPresentationClassAttribute(PresentationClassAttribute.Value.OUTLINE.toString());
			frame2.setPresentationPlaceholderAttribute(new Boolean(true));
			frame2.newDrawTextBoxElement();
			OdfDrawFrame frame3 = (OdfDrawFrame) page.newDrawFrameElement();
			frame3.setProperty(StyleGraphicPropertiesElement.AutoGrowHeight, "true");
			frame3.setProperty(StyleGraphicPropertiesElement.MinHeight, "3.507");
			frame3.setPresentationStyleNameAttribute(frame3.getStyleName());

			frame3.setDrawLayerAttribute("layout");
			frame3.setSvgHeightAttribute("11.62cm");
			frame3.setSvgWidthAttribute("11.857cm");
			frame3.setSvgXAttribute("13.8cm");
			frame3.setSvgYAttribute("4.212cm");
			frame3.setPresentationClassAttribute(PresentationClassAttribute.Value.OUTLINE.toString());
			frame3.setPresentationPlaceholderAttribute(new Boolean(true));
			frame3.newDrawTextBoxElement();

			page.setPresentationPresentationPageLayoutNameAttribute(layoutName);

		}

		OdfPresentationNotes notes = (OdfPresentationNotes) page.newPresentationNotesElement();
		notes.setProperty(StyleDrawingPagePropertiesElement.DisplayHeader, "true");
		notes.setProperty(StyleDrawingPagePropertiesElement.DisplayFooter, "true");
		notes.setProperty(StyleDrawingPagePropertiesElement.DisplayPageNumber, "false");
		notes.setProperty(StyleDrawingPagePropertiesElement.DisplayDateTime, "true");
		OdfDrawPageThumbnail nail = (OdfDrawPageThumbnail) notes.newDrawPageThumbnailElement();
		nail.setProperty(StyleGraphicPropertiesElement.Protect, "size");
		nail.setDrawLayerAttribute("layout");
		nail.setSvgWidthAttribute("11.136cm");
		nail.setSvgHeightAttribute("14.848cm");
		nail.setSvgXAttribute("3.075cm");
		nail.setSvgYAttribute("2.257cm");

		nail.setDrawPageNumberAttribute(new Integer(1));
		nail.setPresentationClassAttribute(PresentationClassAttribute.Value.PAGE.toString());
		OdfDrawFrame frame = (OdfDrawFrame) notes.newDrawFrameElement();
		frame.setProperty(StyleGraphicPropertiesElement.FillColor, "#ffffff");
		frame.setProperty(StyleGraphicPropertiesElement.MinHeight, "13.114");
		frame.setDrawLayerAttribute("layout");
		frame.setSvgWidthAttribute("11.136cm");
		frame.setSvgHeightAttribute("16.799cm");
		frame.setSvgXAttribute("2.1cm");
		frame.setSvgYAttribute("14.107cm");
		frame.setPresentationClassAttribute(PresentationClassAttribute.Value.NOTES.toString());
		frame.setPresentationPlaceholderAttribute(new Boolean(true));
		frame.newDrawTextBoxElement();

		return page;

	}

	private String createUniqueLayoutName() {
		String unique_name;
		unique_name = String.format("a%06x", (int) (Math.random() * 0xffffff));
		return unique_name;
	}

	/** 
	 * The page template type. A page template is a page with some predefine elements.
	 *
	 * we define some template type as below:
	 *
	 * "blank" template is a page without any filled element,
	 *
	 * "title_only" template is a page with a title,
	 *
	 * "title_outline" template is a page with a title and an outline block,
	 *
	 * "title_text" template is a page with a title and a text block,
	 *
	 * "title_twoblock" template is a page with a title two text blocks.
	 */
	public enum TemplatePageType {

		/**
		 * Blank,  a blank presentation
		 */
		DEFAULT("blank"),
		/**
		 * Title_only, the presentation with title only
		 */
		ONLYTITLE("title_only"),
		/**
		 * Title_only, the presentation with outline
		 */
		OUTLINE("title_outline"),
		/**
		 * Title_text, the presentation with title and one text block
		 */
		TEXT("title_text"),
		/**
		 * Title_twoblock, the presentation with title and two text blocks
		 */
		TWOBLOCK("title_twoblock");
		private String mValue;

		TemplatePageType(String aValue) {
			mValue = aValue;
		}

		/**
		 * Return the page template type value.
		 * @return   the template type value
		 */
		public String toString() {
			return mValue;
		}

		/**
		 * Return the name of the template page type.
		 * @param aEnum    a TemplatePageType
		 * @return         the name of page template type
		 */
		public static String toString(TemplatePageType aEnum) {
			return aEnum.toString();
		}

		/**
		 * Return a template page type.
		 * @param aString   the name of the page template type
		 * @return       a TemplatePageType
		 */
		public static TemplatePageType enumValueOf(String aString) {
			for (TemplatePageType aIter : values()) {
				if (aString.equals(aIter.toString())) {
					return aIter;
				}
			}
			return null;
		}
	}
}
