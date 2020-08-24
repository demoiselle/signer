package org.demoiselle.signer.policy.impl.xades.xml;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
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
import org.bouncycastle.util.encoders.Base64;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.policy.impl.xades.SignaturePack;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class XMLSigner{
	
	private KeyStore keyStore;
	private String alias;
	private Document signedDocument;
	private String policyId = "";
	private String id = "id-"+System.currentTimeMillis();
	private SignaturePack sigPack;
	public static final String XMLNS = "http://www.w3.org/2000/09/xmldsig#";
	public static final String XMLNS_DS = "xmlns:ds";
	public static final String XMLNS_XADES = "xmlns:xades";
	public static final String XAdESv1_3_2 = "http://uri.etsi.org/01903/v1.3.2#";

	public XMLSigner(){}
	

	public void setAlias(String alias) {
		this.alias = alias;
	}
	
	public void setKeyStore(KeyStore keyStore) {
		this.keyStore = keyStore;
	}
	
	public void setPolicyId(String policyId) {
		this.policyId = policyId;
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
	
	public byte[] getShaCanonizedValue(String alg, Node xml, String canonical) throws InvalidCanonicalizerException, NoSuchAlgorithmException, CanonicalizationException, ParserConfigurationException, IOException, SAXException {
		Init.init();
		Canonicalizer c14n = Canonicalizer.getInstance(canonical);
		MessageDigest messageDigest = MessageDigest.getInstance(alg);
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
	
	/*private String getIssuerSerialV2(X509Certificate cert) throws IOException {
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
	}*/
	
	private Element addPolicy(Document doc) {
		Element sigPolicyIdentifier = doc.createElementNS(XAdESv1_3_2, "xades:SignaturePolicyIdentifier");

		Element sigPolicyId = doc.createElementNS(XAdESv1_3_2, "xades:SignaturePolicyId");
		sigPolicyIdentifier.appendChild(sigPolicyId);
		
		Element sigPId = doc.createElementNS     (XAdESv1_3_2, "xades:SigPolicyId");
		sigPolicyId .appendChild(sigPId);
		
		Element identifier = doc.createElementNS(XAdESv1_3_2, "xades:Identifier");
		identifier.setTextContent(policyId);
		sigPId.appendChild(identifier);
		
		Element sigTransforms = doc.createElementNS(XMLNS, "ds:Transforms");
		sigPolicyId.appendChild(sigTransforms);
		
		Element sigTransform = doc.createElementNS(XMLNS, "ds:Transform");
		sigTransform.setAttribute("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#");
		sigTransforms.appendChild(sigTransform);
		
		Element sigPolicyHash = doc.createElementNS(XAdESv1_3_2, "xades:SigPolicyHash");
		sigPolicyId.appendChild(sigPolicyHash);
		
		Element sigDigestMethod = doc.createElementNS(XMLNS, "ds:DigestMethod");
		sigDigestMethod.setAttribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256");
		sigPolicyHash.appendChild(sigDigestMethod);
		
		String hash = "";
		
		Document policyDoc = null;
		try {
			policyDoc = PolicyFactory.getInstance().loadXMLPolicy(new XMLChecker().getPolicyByOid(this.policyId)); // "2.16.76.1.7.1.6.2.3"));
			NodeList listHash = policyDoc.getElementsByTagName("pa:SignPolicyDigest");
			if(listHash.getLength() > 0) {
				hash = listHash.item(0).getTextContent();
			}
		} catch (ParserConfigurationException | SAXException | IOException e) {
			e.printStackTrace();
		}
		
		
		Element sigDigestValue = doc.createElementNS(XMLNS, "ds:DigestValue");
		sigDigestValue.setTextContent(hash); //"gh8ZgWP10SSwGxsW1N6d5LpYv3uTt1IAVYU4hj4y0RA=");
		sigPolicyHash.appendChild(sigDigestValue);
		

		Element sigPolicyQualifiers = doc.createElementNS(XAdESv1_3_2, "xades:SigPolicyQualifiers");
		sigPolicyId.appendChild(sigPolicyQualifiers);
		
		Element sigPolicyQualifier = doc.createElementNS(XAdESv1_3_2, "xades:SigPolicyQualifier");
		sigPolicyQualifiers.appendChild(sigPolicyQualifier);
		
		Element sigSPURI = doc.createElementNS(XAdESv1_3_2, "xades:SPURI");
		sigSPURI.setTextContent("http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_3.xml");
		sigPolicyQualifier.appendChild(sigSPURI);
		
		return sigPolicyIdentifier;	
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
		sigTime.setTextContent(signDate+"Z");
		sigSignedProp.appendChild(sigTime);
		
		Element sigCertV2 = doc.createElementNS(XAdESv1_3_2, "xades:SigningCertificate");
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
		
		Element sigIssuerSerial = doc.createElementNS(XAdESv1_3_2, "xades:IssuerSerial");
		//sigIssuerSerial.setTextContent(getIssuerSerialV2(cert));
		sigCert.appendChild(sigIssuerSerial);
		
		String issuerName = cert.getIssuerX500Principal().toString();
		String serialId = cert.getSerialNumber().toString();
				
		//Element sigIssuerSeria = doc.createElementNS(XAdESv1_3_2, "xades:IssuerSerialV2");
		//sigIssuerSerial.setTextContent(getIssuerSerialV2(cert));
		//sigCert.appendChild(sigIssuerSerial);
		

		Element sigIssuerName = doc.createElementNS(XMLNS, "ds:X509IssuerName");
		sigIssuerName.setTextContent(issuerName);
		sigIssuerSerial.appendChild(sigIssuerName);
		
		Element sigIssuerNumber = doc.createElementNS(XMLNS, "ds:X509SerialNumber");
		sigIssuerNumber.setTextContent(serialId);
		sigIssuerSerial.appendChild(sigIssuerNumber);
		
		if(!policyId.isEmpty()) {
			sigSignedProp.appendChild(addPolicy(doc));
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
	
	public Element createSignatureHashReference(Document doc, byte[] signedTagData) {
		
		
		HashMap<String, String> param = new HashMap<String, String>();
		param.put("type", Constants.SignedProperties);
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
		
		Element referenceTag = doc.createElementNS(XMLNS, "ds:Reference");
		if(params.containsKey("id")) {
			referenceTag.setAttribute("Id", params.get("id"));
		}
		referenceTag.setAttribute("Type", params.get("type"));
		referenceTag.setAttribute("URI", params.get("uri"));
		//sigInfTag.appendChild(referenceTag );
		
		if(!params.containsKey("no_transforms")) {
			Element transformsTag = doc.createElementNS(XMLNS, "ds:Transforms");
			referenceTag.appendChild(transformsTag);
			
			if(params.containsKey("alg")){
				Element transformTag = doc.createElementNS(XMLNS, "ds:Transform");
				transformTag.setAttribute("Algorithm", params.get("alg"));
				transformsTag.appendChild(transformTag);
				if(params.containsKey("text")){
					Element xPathTag = doc.createElementNS(XMLNS, "ds:XPath");
					xPathTag.setTextContent(params.get("text"));
					transformTag.appendChild(xPathTag);
				}
			}
			
			if(params.containsKey("transAlg")){
				Element transAlg = doc.createElementNS(XMLNS, "ds:Transform");
				transAlg.setAttribute("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#");;
				transformsTag.appendChild(transAlg);
			}
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
		Document bodyDoc = null;
		
		if(sigPack == SignaturePack.DETACHED){
			bodyDoc = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
		}else {
			bodyDoc = dbf.newDocumentBuilder().parse(
					new InputSource(new InputStreamReader(new FileInputStream(fileName), "UTF-8")));
		}
			
		Element signatureTag = bodyDoc.createElementNS(XMLNS, "ds:Signature");
		signatureTag.setAttribute(XMLNS_DS, XMLNS);
		signatureTag.setAttribute("Id", id);
		
		Element sigInfTag = bodyDoc.createElementNS(XMLNS, "ds:SignedInfo");
		signatureTag.appendChild(sigInfTag);
		
		Element canonicalizationMethodTag = bodyDoc.createElementNS(XMLNS, "ds:CanonicalizationMethod");
		canonicalizationMethodTag.setAttribute("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
		sigInfTag.appendChild(canonicalizationMethodTag);
		
		Element signatureMethodTag = bodyDoc.createElementNS(XMLNS, "ds:SignatureMethod");
		signatureMethodTag.setAttribute("Algorithm", Constants.RSA_SHA256);
		sigInfTag.appendChild(signatureMethodTag );
		
		HashMap<String, String> param = new HashMap<String, String>();
		param.put("type", "");
		param.put("uri", "");
		param.put("id", "r-id-1");
		param.put("text", "not(ancestor-or-self::ds:Signature)");
		param.put("alg", "http://www.w3.org/TR/1999/REC-xpath-19991116");
		param.put("digAlg", Constants.DIGEST_SHA256);
		
		byte[] docHash = null; 
		
		if(sigPack == SignaturePack.DETACHED){
			InputStream inputStream = new FileInputStream(fileName);
			long fileSize = new File(fileName).length();
			docHash = new byte[(int) fileSize];
			inputStream.read(docHash);
			inputStream.close();
			param.put("no_transforms", "true");
			param.put("type", "");
			param.put("uri", Paths.get(fileName).getFileName().toString());
			MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
			param.put("digVal", Base64.toBase64String(messageDigest.digest(docHash)));
			
			Element referenceTag = createReferenceTag(bodyDoc, param);
			sigInfTag.appendChild(referenceTag);
			
			bodyDoc.appendChild(signatureTag);
			
		}else {
			Element docData = getDocumentData(bodyDoc);
			docHash = getShaCanonizedValue("SHA-256", docData, Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
			param.put("type", "");
			param.put("uri", "");
			param.put("id", "r-id-1");
			param.put("text", "not(ancestor-or-self::ds:Signature)");
			param.put("alg", "http://www.w3.org/TR/1999/REC-xpath-19991116");
			param.put("digAlg", Constants.DIGEST_SHA256);
			param.put("transAlg", "http://www.w3.org/2001/10/xml-exc-c14n#");
			param.put("digVal", Base64.toBase64String(docHash));
			
			
			Element referenceTag = createReferenceTag(bodyDoc, param);
			sigInfTag.appendChild(referenceTag);
			
			bodyDoc.getDocumentElement().appendChild(signatureTag);
			
		}
		
		
		return bodyDoc;
	}
	
	
		
	public Document sign(String fileNameSource) throws Throwable{
		//TODO validate policy before sign
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
		
		canonicalized = c14n.canonicalizeSubtree(objectTag.getElementsByTagName("xades:SignedProperties").item(0)); 
		
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
		String result = hash;
		
		signValueTag.setTextContent(result);
		sigTag.appendChild(signValueTag);
		
		
		Element keyInfo = doc.createElementNS(XMLNS, "ds:KeyInfo");
		doc.getElementsByTagName("ds:Signature").item(numSignatures).appendChild(keyInfo);
		
		Element x509 = doc.createElementNS(XMLNS, "ds:X509Data");
		keyInfo.appendChild(x509);
				
		Element x509Certificate = doc.createElementNS(XMLNS, "ds:X509Certificate");
		x509Certificate.setTextContent(Base64.toBase64String(cert.getEncoded()));
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


	public void setSignaturePackaging(SignaturePack pack) {
		sigPack = pack;
		
	}
	
}
