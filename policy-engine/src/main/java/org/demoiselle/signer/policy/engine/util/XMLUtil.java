package org.demoiselle.signer.policy.engine.util;

import java.io.IOException;
import java.io.InputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public class XMLUtil {
	private static final Logger LOGGER = LoggerFactory.getLogger(XMLUtil.class);
    private static MessagesBundle policyMessagesBundle = new MessagesBundle("messages_policy");
	
public static Document loadXMLDocument (InputStream parmIS) {
    
    	DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
    	DocumentBuilder dBuilder = null;
    	Document docReturn = null;
    	try {
			dBuilder = dbFactory.newDocumentBuilder();
		} catch (ParserConfigurationException e) {
			LOGGER.error(policyMessagesBundle.getString("error.xml.parser.notfound", e.getMessage()));
			throw new RuntimeException(policyMessagesBundle.getString("error.xml.parser.notfound", e.getMessage()));
		}
    	try {
    		docReturn = dBuilder.parse(parmIS);
		} catch (SAXException e) {
			LOGGER.error(policyMessagesBundle.getString("error.xml.sax.exception", e.getMessage()));
			throw new RuntimeException(policyMessagesBundle.getString("error.xml.sax.exception", e.getMessage()));
		} catch (IOException e) {
			LOGGER.error(policyMessagesBundle.getString("error.xml.ioexception", e.getMessage()));
			throw new RuntimeException(policyMessagesBundle.getString("error.xml.ioexception", e.getMessage()));
		}
    	return docReturn;
    }
    

}
