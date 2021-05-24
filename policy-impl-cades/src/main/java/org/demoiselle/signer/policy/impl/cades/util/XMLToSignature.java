package org.demoiselle.signer.policy.impl.cades.util;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.LinkedList;

import javax.xml.parsers.ParserConfigurationException;

import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.policy.engine.asn1.etsi.SignPolicyHash;
import org.demoiselle.signer.policy.engine.asn1.etsi.SignaturePolicy;
import org.demoiselle.signer.policy.impl.cades.SignatureInformations;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class XMLToSignature {
	public static SignatureInformations convert(
			Document docPolicy, 
			LinkedList<X509Certificate> chain,
			BasicCertificate cert,
			Date signDate,
			LinkedList<String> validatorErrors,
			LinkedList<String> validatorWarnins) throws ParserConfigurationException, SAXException, IOException {
		
		
		SignatureInformations sigInf = new SignatureInformations();
		
		sigInf.setChain(chain);
		sigInf.setIcpBrasilcertificate(cert);
		//sigInf.setInvalidSignature(invalidSignature);
		sigInf.setNotAfter(cert.getAfterDate());
		
		NodeList policyDigest = docPolicy.getElementsByTagNameNS("http://www.iti.gov.br/PA#", "SignPolicyDigest");
		
		if(policyDigest.getLength() > 0) {
			
			SignaturePolicy sp = new SignaturePolicy();
			SignPolicyHash sph = new SignPolicyHash(null);
			sph.setValue(policyDigest.item(0).getTextContent());
			sp.setSignPolicyHash(sph);
			
			sigInf.setSignaturePolicy(sp);
		}
		
		sigInf.setSignDate(signDate);
		sigInf.setTimeStampSigner(null);
		sigInf.setValidatorErrors(validatorErrors);
		sigInf.setValidatorWarnins(validatorWarnins);
		
		return sigInf;
	}
}
