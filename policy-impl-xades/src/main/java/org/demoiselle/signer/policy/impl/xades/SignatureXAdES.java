package org.demoiselle.signer.policy.impl.xades;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.sun.org.apache.xml.internal.security.Init;
import com.sun.org.apache.xml.internal.security.c14n.CanonicalizationException;
import com.sun.org.apache.xml.internal.security.c14n.Canonicalizer;
import com.sun.org.apache.xml.internal.security.c14n.InvalidCanonicalizerException;

public class SignatureXAdES{
	
	private KeyStore keyStore;
	private String alias;
	private Document signedDocument;
	
	public void setAlias(String alias) {
		this.alias = alias;
	}
	
	public void setKeyStore(KeyStore keyStore) {
		this.keyStore = keyStore;
	}
	
	public static void main(String[] arg) throws Throwable {
		new SignatureXAdES(0);
	}
	
	public SignatureXAdES(int num) throws Exception {
		this.buildXML("/tmp/base.xml");
	}
	
	private byte[] getShaCanonizedValue(String Alg, String xml) throws InvalidCanonicalizerException, NoSuchAlgorithmException, CanonicalizationException, ParserConfigurationException, IOException, SAXException {
		Init.init();
		Canonicalizer c14n = Canonicalizer.getInstance("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
		MessageDigest messageDigest = MessageDigest.getInstance(Alg);
		return messageDigest.digest(c14n.canonicalize(xml.getBytes()));
	}
	
	public Document buildXML(String fileName) throws FileNotFoundException, SAXException, IOException, ParserConfigurationException, InvalidCanonicalizerException, NoSuchAlgorithmException, CanonicalizationException {
		
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		Document bodyDoc = dbf.newDocumentBuilder().parse(
				new InputSource(new InputStreamReader(new FileInputStream(fileName), "UTF-8")));
		
		
		byte[] dh = getShaCanonizedValue("SHA-256", xmlToString(bodyDoc));
		
		Element signatureTag = bodyDoc.createElement("Signature");
		signatureTag.setAttribute("xmlns", "http://www.w3.org/2000/09/xmldsig#");
		
		Element sigInfTag = bodyDoc.createElement("SignedInfo");
		signatureTag.appendChild(sigInfTag);
		
		Element canonicalizationMethodTag = bodyDoc.createElement("CanonicalizationMethod");
		canonicalizationMethodTag.setAttribute("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
		sigInfTag.appendChild(canonicalizationMethodTag);
		
		Element signatureMethodTag = bodyDoc.createElement("SignatureMethod");
		signatureMethodTag.setAttribute("Algorithm", "http://www.w3.org/2000/09/xmldsig#rsa-sha1");
		sigInfTag.appendChild(signatureMethodTag );
		
		Element referenceTag = bodyDoc.createElement("Reference");
		referenceTag.setAttribute("URI", "");
		sigInfTag.appendChild(referenceTag );
		
		Element transformsTag = bodyDoc.createElement("Transforms");
		referenceTag.appendChild(transformsTag);
		
		Element transformTag = bodyDoc.createElement("Transform");
		transformTag.setAttribute("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature");
		transformsTag.appendChild(transformTag);
		
		Element digestMethodTag = bodyDoc.createElement("DigestMethod");
		digestMethodTag.setAttribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256");
		referenceTag.appendChild(digestMethodTag);
		
		Element digestValueTag = bodyDoc.createElement("DigestValue");
		digestValueTag.setTextContent(Base64.toBase64String(dh));
		referenceTag.appendChild(digestValueTag);
		
		bodyDoc.getElementsByTagName("Body").item(0).appendChild(signatureTag);
		
		return(bodyDoc);
	}
	
	public SignatureXAdES(){
	}
		
	public Document sign(String fileNameSource) throws Throwable{
		
		Document doc = buildXML(fileNameSource);
						
		if(keyStore == null) {
			new Throwable("Keystore nula");
		}
		
		X509Certificate cert = (X509Certificate) this.keyStore.getCertificate(alias);
		PrivateKey myPrKey = (PrivateKey) keyStore.getKey(alias, null);
		
		String signedInfo = "<SignedInfo>"+xmlToString(doc.getElementsByTagName("SignedInfo").item(0))+"</SignedInfo>";
		
		Init.init();
		Canonicalizer c14n = Canonicalizer.getInstance("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
		byte[] dh = c14n.canonicalize(signedInfo.getBytes());
		System.out.println(new String(dh));
		
		Signature sig = Signature.getInstance("SHA1withRSA");
		sig.initSign(myPrKey);
		sig.update(dh);
		byte[] s = sig.sign();
		
		Element signValueTag = doc.createElement("SignatureValue");
		String hash = Base64.toBase64String(s);
		String result = splitString(hash);
		
		signValueTag.setTextContent(result);
		doc.getElementsByTagName("Signature").item(0).appendChild(signValueTag);
		
		
		Element keyInfo = doc.createElement("KeyInfo");
		doc.getElementsByTagName("Signature").item(0).appendChild(keyInfo);
		
		Element x509 = doc.createElement("X509Data");
		keyInfo.appendChild(x509);
		
		Element x509Subject = doc.createElement("X509SubjectName");
		x509Subject.setTextContent(cert.getSubjectX500Principal().getName());
		x509.appendChild(x509Subject);
		
		Element x509Certificate = doc.createElement("X509Certificate");
		x509Certificate.setTextContent(splitString(Base64.toBase64String(cert.getEncoded())));
		x509.appendChild(x509Certificate );
		
		
		signedDocument = doc;
		
		return doc;
	}
	
	public void saveSignedDocument(String fileName) throws TransformerException, FileNotFoundException {
		OutputStream os = new FileOutputStream(fileName);
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer trans = tf.newTransformer();
		trans.transform(new DOMSource(signedDocument), new StreamResult(os));
	}
	
	private String splitString(String data) {
		String retVal = "";
		while (data.length() > 75) {
			retVal += data.substring(0, 76)+"\n";
			data = data.substring(76);
		}
		return retVal+data;
	}
	
	public String xmlToString(Node node) {
		StringWriter sw = new StringWriter();
	    Result result = new StreamResult(sw);
	    TransformerFactory factory = TransformerFactory.newInstance();
	    Transformer proc;
		try {
			proc = factory.newTransformer();
		    proc.setOutputProperty(OutputKeys.METHOD, "html");
		    for (int i = 0; i < node.getChildNodes().getLength(); i++)
		    {
		        proc.transform(new DOMSource(node.getChildNodes().item(i)), result);
		    }
		} catch (TransformerConfigurationException e) {
			e.printStackTrace();
		} catch (TransformerException e) {
			e.printStackTrace();
		}
		return sw.toString();
	}
	
	public String xmlToString(Document doc) {
	    DOMSource domSource = new DOMSource(doc);
	    StringWriter writer = new StringWriter();
	    StreamResult result = new StreamResult(writer);
	    TransformerFactory tf = TransformerFactory.newInstance();
	    Transformer transformer;
		try {
			transformer = tf.newTransformer();
			transformer.transform(domSource, result);
		} catch (TransformerConfigurationException e) {
			e.printStackTrace();
		} catch (TransformerException e) {
			e.printStackTrace();
		}
	    
	    return writer.toString();
	}

}
