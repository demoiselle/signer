package org.demoiselle.signer.policy.impl.xades.xml;

import org.demoiselle.signer.policy.impl.xades.xml.impl.XMLSigner;
import org.junit.Before;
import org.junit.Test;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class XMLSignerSURJHomIT {

	private static final String PFX_RESOURCE = "8127_SURJ_2026_R12_00604446000125-senha-senha1.pfx";
	private static final String PFX_PASS = "senha1";
	private static final String XML_RESOURCE = "surj-teste.xml";

	private PrivateKey privateKey;
	private Certificate[] certificateChain;

	@Before
	public void setUp() throws Exception {
		KeyStore ks = KeyStore.getInstance("PKCS12");
		try (InputStream is = getClass().getClassLoader().getResourceAsStream(PFX_RESOURCE)) {
			assertNotNull("PFX resource nao encontrado: " + PFX_RESOURCE, is);
			ks.load(is, PFX_PASS.toCharArray());
		}
		String alias = ks.aliases().nextElement();
		privateKey = (PrivateKey) ks.getKey(alias, PFX_PASS.toCharArray());
		certificateChain = ks.getCertificateChain(alias);
		assertNotNull("PrivateKey nao pode ser nula", privateKey);
		assertNotNull("Certificate chain nao pode ser nula", certificateChain);
	}

	@Test
	public void testSignEnvelopedSURJHom() throws Exception {
		XMLSigner signer = new XMLSigner();
		signer.setPrivateKey(privateKey);
		signer.setCertificateChain(certificateChain);

		InputStream xmlIs = getClass().getClassLoader().getResourceAsStream(XML_RESOURCE);
		assertNotNull("XML resource nao encontrado: " + XML_RESOURCE, xmlIs);

		org.w3c.dom.Document signedDoc = signer.signEnveloped(xmlIs);
		assertNotNull("Documento assinado nao pode ser nulo", signedDoc);

		int sigCount = signedDoc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").getLength();
		assertTrue("Deve haver ao menos 1 assinatura", sigCount > 0);
	}
}
