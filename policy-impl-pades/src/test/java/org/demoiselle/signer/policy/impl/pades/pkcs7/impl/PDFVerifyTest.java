/*
 * Demoiselle Framework
 * Copyright (C) 2016 SERPRO
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

package org.demoiselle.signer.policy.impl.pades.pkcs7.impl;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.core.repository.ConfigurationRepo;
import org.demoiselle.signer.policy.impl.cades.SignatureInformations;
import org.demoiselle.signer.timestamp.Timestamp;
import org.junit.Test;

public class PDFVerifyTest {

//	@Test
	public void testPDFVerify() {

		String filePath ="/";


		List<SignatureInformations> results = new ArrayList<SignatureInformations>();
		PDDocument document;
		try {
			document = PDDocument.load(new File(filePath));
			List<SignatureInformations> result = null;

			Integer rangeMax =0;
			Integer fileLen=0;
			for (PDSignature sig : document.getSignatureDictionaries()) {
				COSDictionary sigDict = sig.getCOSObject();
				COSString contents = (COSString) sigDict.getDictionaryObject(COSName.CONTENTS);
				
				// Recuperando o SigningDate (Date with time-zone) atraves do dicionario M
				Date signingTime = extractDateOfDictM(sigDict.getDictionaryObject(COSName.M));

				byte[] buf = null;

				try (FileInputStream fis = new FileInputStream(filePath)) {
					buf = sig.getSignedContent(fis);
				}

				// Cache LCR
				ConfigurationRepo configlcr = ConfigurationRepo.getInstance();
				//configlcr.setCrlIndex(".crl_index");
				//configlcr.setCrlPath("/home/{usuario}/lcr_cache/");
				configlcr.setOnline(false);

					/* cache interno
					CMSSignedData cms = new CMSSignedData(new CMSProcessableByteArray(buf),contents.getBytes());
			        SignerInformation signerInfo = (SignerInformation) cms.getSignerInfos().getSigners().iterator().next();
			        X509CertificateHolder certificateHolder = (X509CertificateHolder) cms.getCertificates().getMatches(signerInfo.getSID())
			                .iterator().next();
			        X509Certificate varCert = new JcaX509CertificateConverter().getCertificate(certificateHolder);
			        LcrManagerSync.getInstance().update(varCert);
					*/
				PAdESChecker checker = new PAdESChecker();
				byte[] assinatura = contents.getBytes();
				/*
				 *  gravar a assinatura em um arquivo separado

				 */

				File file = new File(filePath + "_.p7s");
				FileOutputStream os = new FileOutputStream(file);
				os.write(assinatura);
				os.flush();
				os.close();

				//System.out.println("validando");
				result = checker.checkDetachedSignature(buf, assinatura);
				checker.getSignaturesInfo().get(0).setSignDate(signingTime);
		        int[] byteRange = sig.getByteRange();
		        rangeMax = (byteRange[byteRange.length-2] + byteRange[byteRange.length-1]);
		        fileLen = (int) new File(filePath).length();

				if (result == null || result.isEmpty()) {
					System.err.println("Erro ao validar");
					assertTrue(false);
				}
				results.addAll(checker.getSignaturesInfo());
			}
			if (fileLen > rangeMax) {
	        	System.err.println("Erro! Foi identificado uma modificação incremental");
	        	assertTrue(false);
	        }

			if (!results.isEmpty()) {

				for (SignatureInformations sis : results) {
					if (sis.isInvalidSignature()) {
						System.err.println("Assinatura inválida");
					}else {
						System.out.println("Assinatura válida");
					}
					
					if (sis.getSignDate() != null) {
						System.out.println("Data da assinatura: " + sis.getSignDate());
						System.out.println("Data da assinatura GMT: " + sis.getSignDateGMT());
					}
					
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
			} else {
				assertTrue(false);
			}
		} catch (Exception e) {
			e.printStackTrace();
			if (!results.isEmpty()) {
				for (SignatureInformations sis : results) {
					for (String valErr : sis.getValidatorErrors()) {
						System.out.println("++++++++++++++ ERROS ++++++++++++++++++");
						System.out.println(valErr);
					}
					for (String valWarn : sis.getValidatorWarnins()) {
						System.err.println("++++++++++++++ AVISOS ++++++++++++++++++");
						System.err.println(valWarn);
					}
					for (X509Certificate cert : sis.getChain()) {
						BasicCertificate certificate = new BasicCertificate(cert);
						if (!certificate.isCACertificate()) {
							System.out.println(certificate.toString());
						}
					}
					if (sis.getSignaturePolicy() != null) {
						System.out.println("------ Politica ----------------- ");
						System.out.println(sis.getSignaturePolicy().toString());

					}

					BasicCertificate bc = sis.getIcpBrasilcertificate();
					if (bc.hasCertificatePF()) {
						System.out.println(bc.getICPBRCertificatePF().getCPF());
					}
					if (bc.hasCertificatePJ()) {
						System.out.println(bc.getICPBRCertificatePJ().getCNPJ());
						System.out.println(bc.getICPBRCertificatePJ().getResponsibleCPF());
					}

				}
				assertTrue(true);
			} else {
				assertTrue(false);
			}
		}
	}
	
	public static Date extractDateOfDictM(COSBase cosNameM) throws ParseException {
		String dateString = cosNameM.toString();
		dateString = dateString.replaceAll("^COSString\\{D:|\\}$", "");
		String gmt = "-"+dateString.split("-")[1].split("'")[0]+"00";
		dateString = dateString.replaceFirst("-\\d{2}'\\d{2}'", gmt);
		SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmssZ");
		Date date = formatter.parse(dateString);
		return date;
	}


	//@Test
	public void testTimeStampOnly() {


		String filePath = "caminho do arquivo";

		PDDocument document;
		try {
			document = PDDocument.load(new File(filePath));
			Timestamp varTimeStamp = null;

			for (PDSignature sig : document.getSignatureDictionaries()) {
				COSDictionary sigDict = sig.getCOSObject();
				COSString contents = (COSString) sigDict.getDictionaryObject(COSName.CONTENTS);
				byte[] buf = null;

				try (FileInputStream fis = new FileInputStream(filePath)) {
					buf = sig.getSignedContent(fis);
				}

				PAdESTimeStampSigner varPAdESTimeStampSigner = new PAdESTimeStampSigner();
				varTimeStamp = varPAdESTimeStampSigner.checkTimeStampPDFWithContent(contents.getBytes(), buf);
			}
			if (varTimeStamp != null) {
				System.out.println("Carimbo do tempo");
				System.out.println(varTimeStamp.getTimeStampAuthorityInfo());
				System.out.println(varTimeStamp.getSerialNumber());
				System.out.println(varTimeStamp.getCertificates());
				System.out.println(varTimeStamp.getTimeStamp());

			}
			assertTrue(true);

		} catch (IOException e) {
			e.printStackTrace();
			assertTrue(false);
		}
	}
}
