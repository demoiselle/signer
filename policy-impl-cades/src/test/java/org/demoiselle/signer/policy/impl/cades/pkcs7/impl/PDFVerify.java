package org.demoiselle.signer.policy.impl.cades.pkcs7.impl;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.policy.impl.cades.SignatureInformations;
import org.junit.Test;

@SuppressWarnings("unused")
public class PDFVerify {

	//@Test
	public void test() {
		
	
			String filePath = "/home/{usuario}/arquivo.pdf";
			
			PDDocument document;
			try {
				document = PDDocument.load(new File(filePath));
						List<SignatureInformations> result = null;
			List<SignatureInformations> results = new ArrayList<SignatureInformations>();

			for (PDSignature sig : document.getSignatureDictionaries()) {
					COSDictionary sigDict = sig.getCOSObject();
					COSString contents = (COSString) sigDict.getDictionaryObject(COSName.CONTENTS);
					FileInputStream fis = new FileInputStream(filePath);
					byte[] buf = null;

					try {
						buf = sig.getSignedContent(fis);
					} finally {
						fis.close();
					}

					CAdESChecker checker = new CAdESChecker();
					result = checker.checkDetachedSignature(buf, contents.getBytes());
					if (result == null || result.isEmpty()) {
						assertTrue(false);
						//Erro
					}
					results.addAll(checker.getSignaturesInfo());
				}
			for (SignatureInformations sis : results){
				for (String valErr : sis.getValidatorErrors()){
					System.out.println( "++++++++++++++ ERROS ++++++++++++++++++");
					System.out.println(valErr);
				}
				for(X509Certificate cert : sis.getChain()){
					BasicCertificate certificate = new BasicCertificate(cert);
					if (!certificate.isCACertificate()){
						System.out.println(certificate.toString());
					}												
				}
				if (sis.getSignaturePolicy() != null){
					System.out.println("------ Politica ----------------- ");
					System.out.println(sis.getSignaturePolicy().toString());
					
				}
				/*
				for (BasicCertificate bc : sis.getSignersBasicCertificates()){
					if (bc.hasCertificatePF()){
						System.out.println(bc.getICPBRCertificatePF().getCPF());
					}
					if (bc.hasCertificatePJ()){
						System.out.println(bc.getICPBRCertificatePJ().getCNPJ());
						System.out.println(bc.getICPBRCertificatePJ().getResponsibleCPF());
					}					 
				}*/
			}			
			assertTrue(true);
			
		} catch (IOException e) {	
			e.printStackTrace();
			assertTrue(false);
		}
	}
}


