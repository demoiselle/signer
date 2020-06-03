package org.demoiselle.signer.policy.impl.xades.xml;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.HashMap;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.Transform;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.encoders.Base64;
import org.demoiselle.signer.policy.impl.xades.SignaturePack;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import sun.misc.IOUtils;


//import com.sun.org.apache.xml.internal.security.Init;
//import com.sun.org.apache.xml.internal.security.c14n.CanonicalizationException;
//import com.sun.org.apache.xml.internal.security.c14n.Canonicalizer;
//import com.sun.org.apache.xml.internal.security.c14n.InvalidCanonicalizerException;


public class XMLSigner{
	
	private KeyStore keyStore;
	private String alias;
	private Document signedDocument;
	private String policyId = "";
	private String id = "id-7d3a7229c93d20fd8fa2cb4b96afe48f"; //+System.currentTimeMillis();
	private SignaturePack sigPack;
	public static final String XMLNS = "http://www.w3.org/2000/09/xmldsig#";
	public static final String XMLNS_DS = "xmlns:ds";
	public static final String XMLNS_XADES = "xmlns:xades";
	public static final String XAdESv1_3_2 = "http://uri.etsi.org/01903/v1.3.2#";

	
	public void setAlias(String alias) {
		this.alias = alias;
	}
	
	public void setKeyStore(KeyStore keyStore) {
		this.keyStore = keyStore;
	}
	
	public void setPolicyId(String policyId) {
		this.policyId = policyId;
	}
	
	public static void main(String[] arg) throws Throwable {
		new XMLSigner(0);
	}
	
	public XMLSigner(int num) throws Exception {
		this.buildXML("/tmp/base.xml");
	}
	
	public Element getDocumentData(Document doc) throws IOException, SAXException, ParserConfigurationException {
		
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		DocumentBuilder builder = dbf.newDocumentBuilder();
		dbf.setNamespaceAware(true);
		Document bodyDoc = builder.newDocument(); 
		Node body = bodyDoc.importNode(doc.getDocumentElement(), true);
		bodyDoc.appendChild(body);
		NodeList signatures = bodyDoc.getElementsByTagName("ds:Signature");
		for(int i = 0; i < signatures.getLength(); i++)
			signatures.item(i).getParentNode().removeChild(signatures.item(i));
		
		
		return bodyDoc.getDocumentElement();
		
	}
	
	private byte[] getShaCanonizedValue(String Alg, Node xml) throws InvalidCanonicalizerException, NoSuchAlgorithmException, CanonicalizationException, ParserConfigurationException, IOException, SAXException {
		Init.init();
		Canonicalizer c14n = Canonicalizer.getInstance("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
		MessageDigest messageDigest = MessageDigest.getInstance(Alg);
		return messageDigest.digest(c14n.canonicalizeSubtree(xml));
	}
	
	private String getCertificateDigest(X509Certificate cert, String algorithm) throws Exception {
		try {
		MessageDigest md = MessageDigest.getInstance(algorithm);
		byte[] digestValue = md.digest(cert.getEncoded());
		return Base64.toBase64String(digestValue);
		}catch (Exception e) {
			throw new Exception("Erro ao gerar resumo do certificado");
		}
	}
	
	private String getIssuerSerial(X509Certificate cert) throws IOException {
		X500Name issuerX500Name = null;
		try {
			issuerX500Name = new X509CertificateHolder(cert.getEncoded()).getIssuer();
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		final GeneralName generalName = new GeneralName(issuerX500Name);
		final GeneralNames generalNames = new GeneralNames(generalName);
		final BigInteger serialNumber = cert.getSerialNumber();
		final IssuerSerial issuerSerial = new IssuerSerial(generalNames, serialNumber);
		
		return  Base64.toBase64String(issuerSerial.toASN1Primitive().getEncoded(ASN1Encoding.DER));
	}
	
	private Element addPolicy(Document doc) {
		Element sigPolicyIdentifier = doc.createElementNS(XAdESv1_3_2, "xades:SignaturePolicyIdentifier");

		Element sigPolicyId = doc.createElementNS(XAdESv1_3_2, "xades:SignaturePolicyId");
		sigPolicyIdentifier.appendChild(sigPolicyId);
		
		Element sigPId = doc.createElementNS(XAdESv1_3_2, "xades:SignaturePolicyId");
		sigPolicyId.appendChild(sigPId);
		
		Element identifier = doc.createElementNS(XAdESv1_3_2, "xades:Identifier");
		identifier.setTextContent(policyId);
		sigPId.appendChild(identifier);
		
		return sigPolicyId;	
	}
	
	
	private Element signedObject(X509Certificate cert, Document doc) throws Exception {
		
		
		Element sigObject = doc.createElementNS(XMLNS, "ds:Object");
		
		Element sigQualify = doc.createElementNS(XAdESv1_3_2, "xades:QualifyingProperties");
		sigQualify.setAttribute("xmlns:xades", "http://uri.etsi.org/01903/v1.3.2#");
		sigQualify.setAttribute("Target", "#"+id);
		sigObject.appendChild(sigQualify);
		
		Element sigProp = doc.createElementNS(XAdESv1_3_2, "xades:SignedProperties");
		sigProp.setAttribute("Id", "xades-"+id);
		sigQualify.appendChild(sigProp);
		
		Element sigSignedProp = doc.createElementNS(XAdESv1_3_2, "xades:SignedSignatureProperties");
		sigProp.appendChild(sigSignedProp);
		
		Element sigTime = doc.createElementNS(XAdESv1_3_2, "xades:SigningTime");
		SimpleDateFormat sdt = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
		String signDate = sdt.format(Calendar.getInstance().getTime());
		//sigTime.setTextContent(signDate+"Z");
		sigTime.setTextContent("2020-06-02T16:37:18Z");
		sigSignedProp.appendChild(sigTime);
		
		Element sigCertV2 = doc.createElementNS(XAdESv1_3_2, "xades:SigningCertificateV2");
		sigSignedProp.appendChild(sigCertV2);
		
		Element sigCert = doc.createElementNS(XAdESv1_3_2, "xades:Cert");
		sigCertV2.appendChild(sigCert);
		
		Element sigCertDig = doc.createElementNS(XAdESv1_3_2, "xades:CertDigest");
		sigCert.appendChild(sigCertDig);
		
		Element sigDigMet = doc.createElementNS(XMLNS, "ds:DigestMethod");
		sigDigMet.setAttribute("Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1");
		sigCertDig.appendChild(sigDigMet);
		
		Element sigDigValue = doc.createElementNS(XMLNS, "ds:DigestValue");
		sigDigValue.setTextContent(getCertificateDigest(cert, "SHA1"));
		sigCertDig.appendChild(sigDigValue);
		
		Element sigIssuerSeria = doc.createElementNS(XAdESv1_3_2, "xades:IssuerSerialV2");
		sigIssuerSeria.setTextContent(getIssuerSerial(cert));
		sigCert.appendChild(sigIssuerSeria);
		
		if(!policyId.isEmpty()) {
			sigProp.appendChild(addPolicy(doc));
		}
		
		Element sigSigDataObjeProp = doc.createElementNS(XAdESv1_3_2, "xades:SignedDataObjectProperties");
		sigProp.appendChild(sigSigDataObjeProp);
		
		Element sigDataObjFormat = doc.createElementNS(XAdESv1_3_2, "xades:DataObjectFormat");
		sigDataObjFormat.setAttribute("ObjectReference", "#r-id-1");
		sigSigDataObjeProp.appendChild(sigDataObjFormat);
		
		Element sigMimeType = doc.createElementNS(XAdESv1_3_2, "xades:MimeType");
		sigMimeType.setTextContent("text/xml");
		sigDataObjFormat.appendChild(sigMimeType);
		
		return sigObject;
	
	}
	
	private Element createSignatureHashReference(Document doc, byte[] signedTagData) {
		
		
		HashMap<String, String> param = new HashMap<String, String>();
		param.put("type", "http://uri.etsi.org/01903#SignedProperties");
		param.put("uri", "#xades-"+id);
		param.put("alg", "http://www.w3.org/2001/10/xml-exc-c14n#");
		param.put("digAlg", "http://www.w3.org/2001/04/xmlenc#sha256");
		
		MessageDigest md = null;
		
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		byte[] digestValue = md.digest(signedTagData);
		param.put("digVal", Base64.toBase64String(digestValue));
		
		return createReferenceTag(doc, param);
	}
	
	private Element createReferenceTag(Document doc, HashMap<String, String>params) {
		//String type, String uri, String id, String text, String alg
		Element referenceTag = doc.createElementNS(XMLNS, "ds:Reference");
		if(params.containsKey("id")) {
			referenceTag.setAttribute("Id", params.get("id"));
		}
		referenceTag.setAttribute("Type", params.get("type"));
		referenceTag.setAttribute("URI", params.get("uri"));
		//sigInfTag.appendChild(referenceTag );
		
		Element transformsTag = doc.createElementNS(XMLNS, "ds:Transforms");
		referenceTag.appendChild(transformsTag);
		
		Element transformTag = doc.createElementNS(XMLNS, "ds:Transform");
		transformTag.setAttribute("Algorithm", params.get("alg"));
		transformsTag.appendChild(transformTag);
		
		if(params.containsKey("text")){
			Element xPathTag = doc.createElementNS(XMLNS, "ds:XPath");
			xPathTag.setTextContent(params.get("text"));
			transformTag.appendChild(xPathTag);
		}
		
		if(params.containsKey("transAlg")){
			Element transAlg = doc.createElementNS(XMLNS, "ds:Transform");
			transAlg.setAttribute("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#");;
			transformsTag.appendChild(transAlg);
		}
		
		if(params.containsKey("digAlg")) { 
			Element digMethodTag = doc.createElementNS(XMLNS, "ds:DigestMethod");
			digMethodTag.setAttribute("Algorithm", params.get("digAlg"));
			referenceTag.appendChild(digMethodTag);
			
			digMethodTag = doc.createElementNS(XMLNS, "ds:DigestValue");
			digMethodTag.setTextContent(params.get("digVal"));
			referenceTag.appendChild(digMethodTag);
		}
			
		return referenceTag;
	}
	
	private Document buildXML(String fileName) throws FileNotFoundException, SAXException, IOException, ParserConfigurationException, InvalidCanonicalizerException, NoSuchAlgorithmException, CanonicalizationException {
		
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		Document bodyDoc = dbf.newDocumentBuilder().parse(
				new InputSource(new InputStreamReader(new FileInputStream(fileName), "UTF-8")));
		Element docData = getDocumentData(bodyDoc);
		Element signatureTag = bodyDoc.createElementNS(XMLNS, "ds:Signature");
		signatureTag.setAttribute(XMLNS_DS, XMLNS);
		signatureTag.setAttribute("Id", id);
		
		Element sigInfTag = bodyDoc.createElementNS(XMLNS, "ds:SignedInfo");
		signatureTag.appendChild(sigInfTag);
		
		Element canonicalizationMethodTag = bodyDoc.createElementNS(XMLNS, "ds:CanonicalizationMethod");
		canonicalizationMethodTag.setAttribute("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
		sigInfTag.appendChild(canonicalizationMethodTag);
		
		Element signatureMethodTag = bodyDoc.createElementNS(XMLNS, "ds:SignatureMethod");
		signatureMethodTag.setAttribute("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
		sigInfTag.appendChild(signatureMethodTag );
		
		HashMap<String, String> param = new HashMap<String, String>();
		param.put("type", "");
		param.put("uri", "");
		param.put("id", "r-id-1");
		param.put("text", "not(ancestor-or-self::ds:Signature)");
		param.put("alg", "http://www.w3.org/TR/1999/REC-xpath-19991116");
		param.put("digAlg", "http://www.w3.org/2001/04/xmlenc#sha256");
		
		byte[] docHash = getShaCanonizedValue("SHA-256", docData); //bodyDoc.getDocumentElement().getFirstChild());
		param.put("digVal", Base64.toBase64String(docHash));
		param.put("transAlg", "http://www.w3.org/2001/10/xml-exc-c14n#");
		
		Element referenceTag = createReferenceTag(bodyDoc, param);
		sigInfTag.appendChild(referenceTag);
		
		bodyDoc.getDocumentElement().appendChild(signatureTag);
		
		return bodyDoc;
	}
	
	public XMLSigner(){
	}
		
	public Document sign(String fileNameSource) throws Throwable{
		
		Init.init();
		
		Document doc = buildXML(fileNameSource);
						
		if(keyStore == null) {
			new Throwable("Keystore nula");
		}
		
		if(alias == null)
			alias = "";
		
		X509Certificate cert = (X509Certificate) this.keyStore.getCertificate(alias);
		PrivateKey myPrKey = (PrivateKey) keyStore.getKey (alias, null);
		
		int numSignatures = doc.getElementsByTagName("ds:Signature").getLength() - 1;
		
		Element sigTag = (Element) doc.getElementsByTagName("ds:Signature").item(numSignatures);
		
		Element objectTag = signedObject(cert, doc);
		
		Init.init();
		Canonicalizer c14n = Canonicalizer.getInstance(CanonicalizationMethod.EXCLUSIVE);
		
		byte[] canonicalized = null;
		
		if(sigPack != SignaturePack.DETACHED){
			canonicalized = c14n.canonicalizeSubtree(objectTag.getElementsByTagName("xades:SignedProperties").item(0)); 
		}else {
			canonicalized = null;
		}
		
		Element sigRefTag = createSignatureHashReference(doc, canonicalized);
		doc.getElementsByTagName("ds:SignedInfo").item(numSignatures).appendChild(sigRefTag);
		
		c14n = Canonicalizer.getInstance(CanonicalizationMethod.INCLUSIVE);
		byte[] dh = c14n.canonicalizeSubtree(doc.getElementsByTagName("ds:SignedInfo").item(numSignatures));
		
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initSign(myPrKey);
		sig.update(dh);
		byte[] s = sig.sign();
		
		Element signValueTag = doc.createElementNS(XMLNS, "ds:SignatureValue");
		signValueTag.setAttribute("Id", "value-"+id);
		String hash = Base64.toBase64String(s);
		String result = splitString(hash);
		
		signValueTag.setTextContent(result);
		sigTag.appendChild(signValueTag);
		
		
		Element keyInfo = doc.createElementNS(XMLNS, "ds:KeyInfo");
		doc.getElementsByTagName("ds:Signature").item(numSignatures).appendChild(keyInfo);
		
		Element x509 = doc.createElementNS(XMLNS, "ds:X509Data");
		keyInfo.appendChild(x509);
				
		Element x509Certificate = doc.createElementNS(XMLNS, "ds:X509Certificate");
		x509Certificate.setTextContent(splitString(Base64.toBase64String(cert.getEncoded())));
		x509.appendChild(x509Certificate );
		
		sigTag.appendChild(objectTag);
		
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
		return data;
		/*
		String retVal = "";
		while (data.length() > 75) {
			retVal += data.substring(0, 76)+"\n";
			data = data.substring(76);
		}
		return retVal+data;*/
	}
	

}
