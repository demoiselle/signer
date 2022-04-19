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

package org.demoiselle.signer.policy.impl.xades.xml;

import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.policy.impl.xades.XMLPoliciesOID;
import org.demoiselle.signer.policy.impl.xades.XMLSignatureInformations;
import org.demoiselle.signer.policy.impl.xades.xml.impl.XMLChecker;
import org.junit.Test;

import java.io.File;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertTrue;

public class XMLCheckerTest {

	//@Test
	public void testWithFile() {

		try {

			//String fileName = "/";
			

			String fileName = "teste_assinatura_rt_signed.xml";
			ClassLoader classLoader = getClass().getClassLoader();
			URL fileUri = classLoader.getResource(fileName);
			File newFile = new File(fileUri.toURI());


			// Cache LCR
			// ConfigurationRepo configlcr = ConfigurationRepo.getInstance();
			// configlcr.setCrlIndex(".crl_index");
			// configlcr.setCrlPath("/home/{usuario}/lcr_cache/");
			// configlcr.setOnline(false);


			XMLChecker xadesChecker = new XMLChecker();
			if (xadesChecker.check(true, newFile.getPath())) {

				List<XMLSignatureInformations> results = new ArrayList<XMLSignatureInformations>();
				results = xadesChecker.getSignaturesInfo();
				if (!results.isEmpty()) {
					for (XMLSignatureInformations sis : results) {
						for (String valErr : sis.getValidatorErrors()) {
							System.err.println("++++++++++++++ ERROS ++++++++++++++++++");
							System.err.println(valErr);
						}

						for (String valWarn : sis.getValidatorWarnins()) {
							System.err.println("++++++++++++++ AVISOS ++++++++++++++++++");
							System.err.println(valWarn);
						}

						if (sis.getSignaturePolicy() != null) {
							System.out.println("------ Politica ----------------- ");
							System.out.println(sis.getSignaturePolicy().getIdentifier());
							String[] policyOIDArray = sis.getSignaturePolicy().getIdentifier().split(":");
							System.out.println(XMLPoliciesOID.getPolicyNameByOID(policyOIDArray[2]));
						}

						BasicCertificate bc = sis.getIcpBrasilcertificate();
						System.out.println(bc.toString());
						if (bc.hasCertificatePF()) {
							System.out.println(bc.getICPBRCertificatePF().getCPF());
						}
						if (bc.hasCertificatePJ()) {
							System.out.println(bc.getICPBRCertificatePJ().getCNPJ());
							System.out.println(bc.getICPBRCertificatePJ().getResponsibleCPF());
						}

						if (sis.getTimeStampSigner() != null) {
							System.out.println(sis.getTimeStampSigner().toString());
						}
					}
					assertTrue(true);
				}
			} else {
				List<XMLSignatureInformations> results = new ArrayList<XMLSignatureInformations>();
				results = xadesChecker.getSignaturesInfo();
				if (!results.isEmpty()) {
					for (XMLSignatureInformations sis : results) {
						for (String valErr : sis.getValidatorErrors()) {
							System.err.println("++++++++++++++ ERROS ++++++++++++++++++");
							System.err.println(valErr);
						}
					}
				}

				assertTrue(false);
			}

		} catch (Throwable e) {
			e.printStackTrace();
			assertTrue(false);
		}
	}

	//@Test
	public void testWithByteArray() {

		try {

			String xmlFile = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><raiz>\n"
				+ " <documento>um documento</documento>\n"
				+ " <conteudo>texto para assinar</conteudo>\n"
				+ "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\" Id=\"id-1627489348420\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><ds:Reference Id=\"r-id-1\" Type=\"\" URI=\"\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/TR/1999/REC-xpath-19991116\"><ds:XPath>not(ancestor-or-self::ds:Signature)</ds:XPath></ds:Transform><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#WithComments\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>qn1BYlIwhsH+KmBZcD75UN3vk20QAWE78YzQKUPFCVs=</ds:DigestValue></ds:Reference><ds:Reference Type=\"http://uri.etsi.org/01903#SignedProperties\" URI=\"#xades-id-1627489348420\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#WithComments\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>IxtHn5zB7PF9qIrUz4rNVCquNmch9TTZw/GSMpHTh1U=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue Id=\"value-id-1627489348420\">HQiKQxLJ7C01NVwUn9b0dD8qNYZoSW1ozH89kgDT71sqWzgZ9MTiUX+ByMl/7CLIGyOz4iaK0GrOeZAIZn+nswA/InYCNtnUigniXNUOwbixGVZdeB/7mTDep9gW6oE9Jipv3L6Rnx+5PyJSMkZqW69LKCdOaMPKkI8XNcShKjJnHFgczbNdoqc9GuCCFJsswSravqAAC7jQNIsZBdyTz/u/xmQe9O9n0xvfbwzzz0LWl0XyjuA1b90ZNaEgeHGxQNBh0tCOu9iwGbAZxLyduH+exHLNUdHBcLtNZh+xtRwAWgCUjSTxsTpvK9dlnPGEakBhoAnveO7eylpaQ+opGQ==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509SubjectName>CN=EMERSON SACHIO SAITO:80621732915, OU=RFB e-CPF A3, OU=ARSERPRO, OU=Secretaria da Receita Federal do Brasil - RFB, O=ICP-Brasil, C=BR</ds:X509SubjectName><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo><ds:Object><xades:QualifyingProperties Target=\"#id-1627489348420\"><xades:SignedProperties Id=\"xades-id-1627489348420\"><xades:SignedSignatureProperties><xades:SigningTime>2021-07-28T13:22:30Z</xades:SigningTime><xades:SigningCertificate><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>njzMA7rYCCQaHU0+7s+o58o5Jgw=</ds:DigestValue></xades:CertDigest><xades:IssuerSerial><ds:X509IssuerName>CN=Autoridade Certificadora SERPRORFBv5, OU=Secretaria da Receita Federal do Brasil - RFB, O=ICP-Brasil, C=BR</ds:X509IssuerName><ds:X509SerialNumber>17347171</ds:X509SerialNumber></xades:IssuerSerial></xades:Cert></xades:SigningCertificate><xades:SignaturePolicyIdentifier><xades:SignaturePolicyId><xades:SigPolicyId><xades:Identifier Qualifier=\"OIDAsURN\">urn:oid:2.16.76.1.7.1.7.2.4</xades:Identifier></xades:SigPolicyId><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#WithComments\"/></ds:Transforms><xades:SigPolicyHash><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>fQ9XHn48E2jgyG/zu02V5o5Ib5KXcRygVhCHA38CO1E=</ds:DigestValue></xades:SigPolicyHash><xades:SigPolicyQualifiers><xades:SigPolicyQualifier><xades:SPURI>http://politicas.icpbrasil.gov.br/PA_AD_RT_v2_4.xml</xades:SPURI></xades:SigPolicyQualifier></xades:SigPolicyQualifiers></xades:SignaturePolicyId></xades:SignaturePolicyIdentifier></xades:SignedSignatureProperties><xades:SignedDataObjectProperties><xades:DataObjectFormat ObjectReference=\"#r-id-1\"><xades:MimeType>text/xml</xades:MimeType></xades:DataObjectFormat></xades:SignedDataObjectProperties></xades:SignedProperties><xades:UnsignedProperties><xades:UnsignedSignatureProperties><xades:SignatureTimeStamp><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#WithComments\"/><xades:EncapsulatedTimeStamp Id=\"TimeStampid-1627489348420\">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</xades:EncapsulatedTimeStamp></xades:SignatureTimeStamp></xades:UnsignedSignatureProperties></xades:UnsignedProperties></xades:QualifyingProperties></ds:Object></ds:Signature></raiz>";

			byte[] contentXml = xmlFile.getBytes();

			// Cache LCR
			// ConfigurationRepo configlcr = ConfigurationRepo.getInstance();
			// configlcr.setCrlIndex(".crl_index");
			// configlcr.setCrlPath("/home/{usuario}/lcr_cache/");
			// configlcr.setOnline(false);

			/*
			 * cache interno CMSSignedData cms = new CMSSignedData(new
			 * CMSProcessableByteArray(buf),contents.getBytes()); SignerInformation
			 * signerInfo = (SignerInformation)
			 * cms.getSignerInfos().getSigners().iterator().next(); X509CertificateHolder
			 * certificateHolder = (X509CertificateHolder)
			 * cms.getCertificates().getMatches(signerInfo.getSID()) .iterator().next();
			 * X509Certificate varCert = new
			 * JcaX509CertificateConverter().getCertificate(certificateHolder);
			 * LcrManagerSync.getInstance().update(varCert);
			 */

			XMLChecker xadesChecker = new XMLChecker();
			if (xadesChecker.check(contentXml)) {

				List<XMLSignatureInformations> results = new ArrayList<XMLSignatureInformations>();
				results = xadesChecker.getSignaturesInfo();
				if (!results.isEmpty()) {
					for (XMLSignatureInformations sis : results) {
						for (String valErr : sis.getValidatorErrors()) {
							System.err.println("++++++++++++++ ERROS ++++++++++++++++++");
							System.err.println(valErr);
						}

						for (String valWarn : sis.getValidatorWarnins()) {
							System.err.println("++++++++++++++ AVISOS ++++++++++++++++++");
							System.err.println(valWarn);
						}

						if (sis.getSignaturePolicy() != null) {
							System.out.println("------ Politica ----------------- ");
							System.out.println(sis.getSignaturePolicy().toString());

						}

						BasicCertificate bc = sis.getIcpBrasilcertificate();
						System.out.println(bc.toString());
						if (bc.hasCertificatePF()) {
							System.out.println(bc.getICPBRCertificatePF().getCPF());
						}
						if (bc.hasCertificatePJ()) {
							System.out.println(bc.getICPBRCertificatePJ().getCNPJ());
							System.out.println(bc.getICPBRCertificatePJ().getResponsibleCPF());
						}

						if (sis.getTimeStampSigner() != null) {
							System.out.println(sis.getTimeStampSigner().toString());
						}
					}
					assertTrue(true);
				}
			} else {
				assertTrue(false);
			}

		} catch (Throwable e) {
			e.printStackTrace();
			assertTrue(false);
		}
	}

	//@Test
	public void testWithInputStream() {

		try {

			String fileName = "teste_assinatura_rt_signed.xml";
			ClassLoader classLoader = getClass().getClassLoader();

			// Cache LCR
			// ConfigurationRepo configlcr = ConfigurationRepo.getInstance();
			// configlcr.setCrlIndex(".crl_index");
			// configlcr.setCrlPath("/home/{usuario}/lcr_cache/");
			// configlcr.setOnline(false);

			/*
			 * cache interno CMSSignedData cms = new CMSSignedData(new
			 * CMSProcessableByteArray(buf),contents.getBytes()); SignerInformation
			 * signerInfo = (SignerInformation)
			 * cms.getSignerInfos().getSigners().iterator().next(); X509CertificateHolder
			 * certificateHolder = (X509CertificateHolder)
			 * cms.getCertificates().getMatches(signerInfo.getSID()) .iterator().next();
			 * X509Certificate varCert = new
			 * JcaX509CertificateConverter().getCertificate(certificateHolder);
			 * LcrManagerSync.getInstance().update(varCert);
			 */

			XMLChecker xadesChecker = new XMLChecker();
			if (xadesChecker.check(classLoader.getResourceAsStream(fileName))) {

				List<XMLSignatureInformations> results = new ArrayList<XMLSignatureInformations>();
				results = xadesChecker.getSignaturesInfo();
				if (!results.isEmpty()) {
					for (XMLSignatureInformations sis : results) {
						for (String valErr : sis.getValidatorErrors()) {
							System.err.println("++++++++++++++ ERROS ++++++++++++++++++");
							System.err.println(valErr);
						}

						for (String valWarn : sis.getValidatorWarnins()) {
							System.err.println("++++++++++++++ AVISOS ++++++++++++++++++");
							System.err.println(valWarn);
						}

						if (sis.getSignaturePolicy() != null) {
							System.out.println("------ Politica ----------------- ");
							System.out.println(sis.getSignaturePolicy().toString());

						}

						BasicCertificate bc = sis.getIcpBrasilcertificate();
						System.out.println(bc.toString());
						if (bc.hasCertificatePF()) {
							System.out.println(bc.getICPBRCertificatePF().getCPF());
						}
						if (bc.hasCertificatePJ()) {
							System.out.println(bc.getICPBRCertificatePJ().getCNPJ());
							System.out.println(bc.getICPBRCertificatePJ().getResponsibleCPF());
						}

						if (sis.getTimeStampSigner() != null) {
							System.out.println(sis.getTimeStampSigner().toString());
						}
					}
					assertTrue(true);
				}
			} else {
				assertTrue(false);
			}

		} catch (Throwable e) {
			e.printStackTrace();
			assertTrue(false);
		}
	}


	//@Test
	public void testWithString() {

		try {

			String xmlFile = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><raiz>\n <documento>um documento</documento>\n <conteudo>texto para assinar</conteudo>\n<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\" Id=\"id-1627489348420\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><ds:Reference Id=\"r-id-1\" Type=\"\" URI=\"\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/TR/1999/REC-xpath-19991116\"><ds:XPath>not(ancestor-or-self::ds:Signature)</ds:XPath></ds:Transform><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#WithComments\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>qn1BYlIwhsH+KmBZcD75UN3vk20QAWE78YzQKUPFCVs=</ds:DigestValue></ds:Reference><ds:Reference Type=\"http://uri.etsi.org/01903#SignedProperties\" URI=\"#xades-id-1627489348420\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#WithComments\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>IxtHn5zB7PF9qIrUz4rNVCquNmch9TTZw/GSMpHTh1U=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue Id=\"value-id-1627489348420\">HQiKQxLJ7C01NVwUn9b0dD8qNYZoSW1ozH89kgDT71sqWzgZ9MTiUX+ByMl/7CLIGyOz4iaK0GrOeZAIZn+nswA/InYCNtnUigniXNUOwbixGVZdeB/7mTDep9gW6oE9Jipv3L6Rnx+5PyJSMkZqW69LKCdOaMPKkI8XNcShKjJnHFgczbNdoqc9GuCCFJsswSravqAAC7jQNIsZBdyTz/u/xmQe9O9n0xvfbwzzz0LWl0XyjuA1b90ZNaEgeHGxQNBh0tCOu9iwGbAZxLyduH+exHLNUdHBcLtNZh+xtRwAWgCUjSTxsTpvK9dlnPGEakBhoAnveO7eylpaQ+opGQ==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509SubjectName>CN=EMERSON SACHIO SAITO:80621732915, OU=RFB e-CPF A3, OU=ARSERPRO, OU=Secretaria da Receita Federal do Brasil - RFB, O=ICP-Brasil, C=BR</ds:X509SubjectName><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo><ds:Object><xades:QualifyingProperties Target=\"#id-1627489348420\"><xades:SignedProperties Id=\"xades-id-1627489348420\"><xades:SignedSignatureProperties><xades:SigningTime>2021-07-28T13:22:30Z</xades:SigningTime><xades:SigningCertificate><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>njzMA7rYCCQaHU0+7s+o58o5Jgw=</ds:DigestValue></xades:CertDigest><xades:IssuerSerial><ds:X509IssuerName>CN=Autoridade Certificadora SERPRORFBv5, OU=Secretaria da Receita Federal do Brasil - RFB, O=ICP-Brasil, C=BR</ds:X509IssuerName><ds:X509SerialNumber>17347171</ds:X509SerialNumber></xades:IssuerSerial></xades:Cert></xades:SigningCertificate><xades:SignaturePolicyIdentifier><xades:SignaturePolicyId><xades:SigPolicyId><xades:Identifier Qualifier=\"OIDAsURN\">urn:oid:2.16.76.1.7.1.7.2.4</xades:Identifier></xades:SigPolicyId><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#WithComments\"/></ds:Transforms><xades:SigPolicyHash><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>fQ9XHn48E2jgyG/zu02V5o5Ib5KXcRygVhCHA38CO1E=</ds:DigestValue></xades:SigPolicyHash><xades:SigPolicyQualifiers><xades:SigPolicyQualifier><xades:SPURI>http://politicas.icpbrasil.gov.br/PA_AD_RT_v2_4.xml</xades:SPURI></xades:SigPolicyQualifier></xades:SigPolicyQualifiers></xades:SignaturePolicyId></xades:SignaturePolicyIdentifier></xades:SignedSignatureProperties><xades:SignedDataObjectProperties><xades:DataObjectFormat ObjectReference=\"#r-id-1\"><xades:MimeType>text/xml</xades:MimeType></xades:DataObjectFormat></xades:SignedDataObjectProperties></xades:SignedProperties><xades:UnsignedProperties><xades:UnsignedSignatureProperties><xades:SignatureTimeStamp><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#WithComments\"/><xades:EncapsulatedTimeStamp Id=\"TimeStampid-1627489348420\">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</xades:EncapsulatedTimeStamp></xades:SignatureTimeStamp></xades:UnsignedSignatureProperties></xades:UnsignedProperties></xades:QualifyingProperties></ds:Object></ds:Signature></raiz>";
			// Cache LCR
			// ConfigurationRepo configlcr = ConfigurationRepo.getInstance();
			// configlcr.setCrlIndex(".crl_index");
			// configlcr.setCrlPath("/home/{usuario}/lcr_cache/");
			// configlcr.setOnline(false);

			/*
			 * cache interno CMSSignedData cms = new CMSSignedData(new
			 * CMSProcessableByteArray(buf),contents.getBytes()); SignerInformation
			 * signerInfo = (SignerInformation)
			 * cms.getSignerInfos().getSigners().iterator().next(); X509CertificateHolder
			 * certificateHolder = (X509CertificateHolder)
			 * cms.getCertificates().getMatches(signerInfo.getSID()) .iterator().next();
			 * X509Certificate varCert = new
			 * JcaX509CertificateConverter().getCertificate(certificateHolder);
			 * LcrManagerSync.getInstance().update(varCert);
			 */

			XMLChecker xadesChecker = new XMLChecker();
			if (xadesChecker.check(xmlFile)) {

				List<XMLSignatureInformations> results = new ArrayList<XMLSignatureInformations>();
				results = xadesChecker.getSignaturesInfo();
				if (!results.isEmpty()) {
					for (XMLSignatureInformations sis : results) {
						for (String valErr : sis.getValidatorErrors()) {
							System.err.println("++++++++++++++ ERROS ++++++++++++++++++");
							System.err.println(valErr);
						}

						for (String valWarn : sis.getValidatorWarnins()) {
							System.err.println("++++++++++++++ AVISOS ++++++++++++++++++");
							System.err.println(valWarn);
						}

						if (sis.getSignaturePolicy() != null) {
							System.out.println("------ Politica ----------------- ");
							System.out.println(sis.getSignaturePolicy().toString());

						}

						BasicCertificate bc = sis.getIcpBrasilcertificate();
						System.out.println(bc.toString());
						if (bc.hasCertificatePF()) {
							System.out.println(bc.getICPBRCertificatePF().getCPF());
						}
						if (bc.hasCertificatePJ()) {
							System.out.println(bc.getICPBRCertificatePJ().getCNPJ());
							System.out.println(bc.getICPBRCertificatePJ().getResponsibleCPF());
						}

						if (sis.getTimeStampSigner() != null) {
							System.out.println(sis.getTimeStampSigner().toString());
						}
					}
					assertTrue(true);
				}
			} else {
				assertTrue(false);
			}

		} catch (Throwable e) {
			e.printStackTrace();
			assertTrue(false);
		}
	}


	// @Test
	public void testDetachedWithFile() {

		try {

			String signaturefileName = "teste_assinatura_rt_detached_signed.xml";
			String fileName = "teste_assinatura.xml";
			ClassLoader classLoader = getClass().getClassLoader();
			URL fileUri = classLoader.getResource(fileName);
			File newFile = new File(fileUri.toURI());
			fileUri = classLoader.getResource(signaturefileName);
			File newSignatureFile = new File(fileUri.toURI());

//	        InputStreamReader streamReader = new InputStreamReader(inputStream, StandardCharsets.UTF_8);
//	        BufferedReader reader = new BufferedReader(streamReader);

			// Cache LCR
			// ConfigurationRepo configlcr = ConfigurationRepo.getInstance();
			// configlcr.setCrlIndex(".crl_index");
			// configlcr.setCrlPath("/home/{usuario}/lcr_cache/");
			// configlcr.setOnline(false);

			/*
			 * cache interno CMSSignedData cms = new CMSSignedData(new
			 * CMSProcessableByteArray(buf),contents.getBytes()); SignerInformation
			 * signerInfo = (SignerInformation)
			 * cms.getSignerInfos().getSigners().iterator().next(); X509CertificateHolder
			 * certificateHolder = (X509CertificateHolder)
			 * cms.getCertificates().getMatches(signerInfo.getSID()) .iterator().next();
			 * X509Certificate varCert = new
			 * JcaX509CertificateConverter().getCertificate(certificateHolder);
			 * LcrManagerSync.getInstance().update(varCert);
			 */

			XMLChecker xadesChecker = new XMLChecker();
			xadesChecker.check(newFile.getPath(), newSignatureFile.getPath());
			List<XMLSignatureInformations> results = new ArrayList<XMLSignatureInformations>();
			results = xadesChecker.getSignaturesInfo();
			if (!results.isEmpty()) {
				for (XMLSignatureInformations sis : results) {
					for (String valErr : sis.getValidatorErrors()) {
						System.err.println("++++++++++++++ ERROS ++++++++++++++++++");
						System.err.println(valErr);
					}

					for (String valWarn : sis.getValidatorWarnins()) {
						System.err.println("++++++++++++++ AVISOS ++++++++++++++++++");
						System.err.println(valWarn);
					}

					if (sis.getSignaturePolicy() != null) {
						System.out.println("------ Politica ----------------- ");
						System.out.println(sis.getSignaturePolicy().toString());

					}

					BasicCertificate bc = sis.getIcpBrasilcertificate();
					System.out.println(bc.toString());
					if (bc.hasCertificatePF()) {
						System.out.println(bc.getICPBRCertificatePF().getCPF());
					}
					if (bc.hasCertificatePJ()) {
						System.out.println(bc.getICPBRCertificatePJ().getCNPJ());
						System.out.println(bc.getICPBRCertificatePJ().getResponsibleCPF());
					}

					if (sis.getTimeStampSigner() != null) {
						System.out.println(sis.getTimeStampSigner().toString());
					}
				}
				assertTrue(true);
			}

		} catch (Throwable e) {
			e.printStackTrace();
			assertTrue(false);
		}
	}

}
