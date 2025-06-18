/*
 * Demoiselle Framework
 * Copyright (C) 2025 SERPRO
 * ----------------------------------------------------------------------------
 * This file is part of Demoiselle Framework.
 *
 * Demoiselle Framework is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License version 3
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License version 3
 * along with this program; if not,  see <http://www.gnu.org/licenses/>
 * or write to the Free Software Foundation, Inc., 51 Franklin Street,
 * Fifth Floor, Boston, MA  02110-1301, USA.
 * ----------------------------------------------------------------------------
 * Este arquivo é parte do Framework Demoiselle.
 *
 * O Framework Demoiselle é um software livre; você pode redistribuí-lo e/ou
 * modificá-lo dentro dos termos da GNU LGPL versão 3 como publicada pela Fundação
 * do Software Livre (FSF).
 *
 * Este programa é distribuído na esperança que possa ser útil, mas SEM NENHUMA
 * GARANTIA; sem uma garantia implícita de ADEQUAÇÃO a qualquer MERCADO ou
 * APLICAÇÃO EM PARTICULAR. Veja a Licença Pública Geral GNU/LGPL em português
 * para maiores detalhes.
 *
 * Você deve ter recebido uma cópia da GNU LGPL versão 3, sob o título
 * "LICENCA.txt", junto com esse programa. Se não, acesse <http://www.gnu.org/licenses/>
 * ou escreva para a Fundação do Software Livre (FSF) Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA 02111-1301, USA.
 */

package org.demoiselle.signer.policy.impl.xmldsig.util;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.demoiselle.signer.core.util.MessagesBundle;
import org.demoiselle.signer.policy.impl.xmldsig.XMLSignerException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * Class for commons XML methods
 *
 * @author Eduardo &lt;edumg80@gmail.com&gt;
 */
public class DocumentUtils {

	private static final Logger logger = LoggerFactory.getLogger(DocumentUtils.class);
	private static MessagesBundle messagesBundle = new MessagesBundle();

	/**
	 * Load XML Document from File name and Location.
	 *
	 * @param xmlFile the XML filename.
	 * @param setElementId search and set Id attributes on generated document.
	 *
	 * @return the document.
	 */
	public static Document loadXMLDocument(String xmlFile, boolean setElementId) throws XMLSignerException {
		try {
			BufferedReader in = new BufferedReader(new FileReader(xmlFile));
			InputSource source = new InputSource(in);
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			Document docRet = dbf.newDocumentBuilder().parse(source);
			docRet.setXmlStandalone(true);
			if (setElementId) {
				setDocumentElementId(docRet);
			}
			return docRet;
		} catch (UnsupportedEncodingException e) {
			logger.error(messagesBundle.getString("erro.unsupported.encoding.exception", "UTF-8"));
			throw new XMLSignerException(messagesBundle.getString("erro.unsupported.encoding.exception", "UTF-8"));
		} catch (FileNotFoundException e) {
			logger.error(messagesBundle.getString("error.file.not.found", xmlFile));
			throw new XMLSignerException(messagesBundle.getString("error.file.not.found", xmlFile));
		} catch (SAXException e) {
			logger.error(messagesBundle.getString("error.xml.parser", e.getMessage()));
			throw new XMLSignerException(messagesBundle.getString("error.xml.parser", e.getMessage()));
		} catch (IOException e) {
			logger.error(messagesBundle.getString("error.io", e.getMessage()));
			throw new XMLSignerException(messagesBundle.getString("error.io", e.getMessage()));
		} catch (ParserConfigurationException e) {
			logger.error(messagesBundle.getString("error.xml.parser", e.getMessage()));
			throw new XMLSignerException(messagesBundle.getString("error.xml.parser", e.getMessage()));
		}
	}
	
	/**
	 * Load XML Document from String that represents a XML file.
	 *
	 * @param xmlString the XML content.
	 * @param setElementId search and set Id attributes on generated document.
	 *
	 * @return the document.
	 */
	public static Document loadXMLDocumentFromString(String xmlString, boolean setElementId) throws XMLSignerException {
		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			Document retDoc = dbf.newDocumentBuilder().parse(new InputSource(new StringReader(xmlString)));
			retDoc.setXmlStandalone(true);
			if (setElementId) {
				setDocumentElementId(retDoc);
			}
			return retDoc;
		} catch (SAXException e) {
			logger.error(messagesBundle.getString("error.xml.parser", e.getMessage()));
			throw new XMLSignerException(messagesBundle.getString("error.xml.parser", e.getMessage()));
		} catch (IOException e) {
			logger.error(messagesBundle.getString("error.io", e.getMessage()));
			throw new XMLSignerException(messagesBundle.getString("error.io", e.getMessage()));
		} catch (ParserConfigurationException e) {
			logger.error(messagesBundle.getString("error.xml.parser", e.getMessage()));
			throw new XMLSignerException(messagesBundle.getString("error.xml.parser", e.getMessage()));
		}
	}
	
	/**
	 * Load XML Document from byte[] that represents a XML file.
	 *
	 * @param xmlContent bytes of XML content.
	 * @param setElementId search and set Id attributes on generated document.
	 *
	 * @return the document.
	 */
	public static Document loadXMLDocument(byte[] xmlContent, boolean setElementId) throws XMLSignerException {
		try {
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			dbFactory.setNamespaceAware(true);
			Document retDoc = dbFactory.newDocumentBuilder().parse(new ByteArrayInputStream(xmlContent));
			retDoc.setXmlStandalone(true);
			if (setElementId) {
				setDocumentElementId(retDoc);
			}
			return retDoc;
		} catch (SAXException e) {
			logger.error(messagesBundle.getString("error.xml.parser", e.getMessage()));
			throw new XMLSignerException(messagesBundle.getString("error.xml.parser", e.getMessage()));
		} catch (IOException e) {
			logger.error(messagesBundle.getString("error.io", e.getMessage()));
			throw new XMLSignerException(messagesBundle.getString("error.io", e.getMessage()));
		} catch (ParserConfigurationException e) {
			logger.error(messagesBundle.getString("error.xml.parser", e.getMessage()));
			throw new XMLSignerException(messagesBundle.getString("error.xml.parser", e.getMessage()));
		}
	}
	
	// Search for "id" attributes and set Id semantic (required for "getElementById")
	public static void setDocumentElementId(Document doc) {
        NodeList nodeList = doc.getElementsByTagName("*");
        for (int n = 0; n < nodeList.getLength(); n++) {
            Node node = nodeList.item(n);
            if (node.getNodeType() == Node.ELEMENT_NODE) {
            	Element element = (Element)node;
            	for (int a = 0; a < element.getAttributes().getLength(); a++) {
            		Node attribute = element.getAttributes().item(a); 
            		if (attribute.getNodeType() == Node.ATTRIBUTE_NODE && "id".equalsIgnoreCase(attribute.getLocalName())) {
            			element.setIdAttributeNode((Attr) attribute, true);
            		}
            	}
            }
        }
	}
	
	public static boolean hasAnyDocumentElementAttribute(NodeList elements, String attributeName) {
		boolean hasNonBlankAttrib = false;
		for (int i = 0; i < elements.getLength(); i++) {
			Element element = (Element) elements.item(i);
			for (int a = 0; a < element.getAttributes().getLength(); a++) {
				Node attribute = element.getAttributes().item(a);
				String value = attribute.getNodeValue();
				if (attributeName.equalsIgnoreCase(attribute.getLocalName()) && value != null && !value.isEmpty()) {
					hasNonBlankAttrib = true;
					break;
				}
			}
			if (hasNonBlankAttrib) {
				break;
			}
		}
		return hasNonBlankAttrib;
	}

	/**
	 * Read content from file.
	 *
	 * @param parmFile the filename.
	 * @return the content.
	 */
	public static byte[] readContent(String parmFile) {
		try {
			byte[] result = null;
			File file = new File(parmFile);
			FileInputStream is = new FileInputStream(parmFile);
			result = new byte[(int) file.length()];
			is.read(result);
			is.close();
			return result;
		} catch (IOException e) {
			logger.error(messagesBundle.getString("error.io", e.getMessage()));
			throw new XMLSignerException(messagesBundle.getString("error.io", e.getMessage()));
		}
	}
}
