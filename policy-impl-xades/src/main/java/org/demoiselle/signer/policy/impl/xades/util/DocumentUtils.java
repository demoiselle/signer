/*
 * Demoiselle Framework
 * Copyright (C) 2021 SERPRO
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

package org.demoiselle.signer.policy.impl.xades.util;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.demoiselle.signer.policy.impl.xades.XMLSignerException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * 
 * @author Emerson Saito <emerson.saito@serpro.gov.br>
 *
 */
public class DocumentUtils {
	
	private static final Logger logger = LoggerFactory.getLogger(DocumentUtils.class);
	private static MessagesBundle xadesMessagesBundle = new MessagesBundle();
	
	public static String getString(Document parmDocument, String parmTagName) {
		
		Element rootElement = parmDocument.getDocumentElement();
        NodeList list = rootElement.getElementsByTagName(parmTagName);
        if (list != null && list.getLength() > 0) {
            NodeList subList = list.item(0).getChildNodes();

            if (subList != null && subList.getLength() > 0) {
                return subList.item(0).getNodeValue();
            }
        }
        return null;
    }
	
	/**
	 * 
	 * @param xmlFile
	 * @return
	 */
	public static Document loadXMLDocument(String xmlFile) {
		Document docReturn= null;
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		try {
			docReturn = dbf.newDocumentBuilder().parse(new InputSource(new InputStreamReader(new FileInputStream(xmlFile), "UTF-8")));
		} catch (UnsupportedEncodingException e) {
			logger.error(xadesMessagesBundle.getString("erro.unsupported.encoding.exception", "UTF-8"));
			throw new XMLSignerException(xadesMessagesBundle.getString("erro.unsupported.encoding.exception", "UTF-8"));
		} catch (FileNotFoundException e) {
			logger.error(xadesMessagesBundle.getString("error.file.not.found", xmlFile));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.file.not.found", xmlFile));
		} catch (SAXException e) {
			logger.error(xadesMessagesBundle.getString("error.xml.parser", e.getMessage()));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.parser", e.getMessage()));
		} catch (IOException e) {
			
			logger.error(xadesMessagesBundle.getString("error.io", e.getMessage()));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.io", e.getMessage()));
		} catch (ParserConfigurationException e) {
			logger.error(xadesMessagesBundle.getString("error.xml.parser", e.getMessage()));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.parser", e.getMessage()));
		}
		return docReturn;
	}
	
	
	public static Element getDocumentData(Document doc) throws XMLSignerException{

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		DocumentBuilder builder;
		Document bodyDoc = null;
		try {
			builder = dbf.newDocumentBuilder();
			dbf.setNamespaceAware(true);
			bodyDoc = builder.newDocument();
			Node body = bodyDoc.importNode(doc.getDocumentElement(), true);
			bodyDoc.appendChild(body);
			NodeList signatures = bodyDoc.getElementsByTagName("ds:Signature");
			for (int i = 0; i < signatures.getLength(); i++)
				signatures.item(i).getParentNode().removeChild(signatures.item(i));
		} catch (ParserConfigurationException e) {
			logger.error(xadesMessagesBundle.getString("error.xml.parser", e.getMessage()));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.parser", e.getMessage()));
		}		
		return bodyDoc.getDocumentElement();	
	}
	
	public static byte[] getShaCanonizedValue(String alg, Node xml, String canonical) throws XMLSignerException{
		Init.init();
		Canonicalizer c14n;
		try {
			c14n = Canonicalizer.getInstance(canonical);
		} catch (InvalidCanonicalizerException e) {
			logger.error(xadesMessagesBundle.getString("error.xml.Invalid.Canonicalizer", e.getMessage()));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.Invalid.Canonicalizer", e.getMessage()));
		}
		MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance(alg);
		} catch (NoSuchAlgorithmException e) {
			logger.error(xadesMessagesBundle.getString("error.no.algorithm", e.getMessage()));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.no.algorithm", e.getMessage()));
		}
		try {
			return messageDigest.digest(c14n.canonicalizeSubtree(xml));
		} catch (CanonicalizationException e) {
			logger.error(xadesMessagesBundle.getString("error.xml.Invalid.Canonicalizer", e.getMessage()));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.Invalid.Canonicalizer", e.getMessage()));
		}
	}

	
}
