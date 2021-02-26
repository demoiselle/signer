package org.demoiselle.signer.policy.impl.pades.pkcs7.impl;

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.StringTokenizer;

import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.core.repository.Configuration;
import org.demoiselle.signer.policy.impl.cades.SignatureInformations;
import org.demoiselle.signer.policy.impl.cades.pkcs7.impl.CAdESTimeStampSigner;
import org.demoiselle.signer.timestamp.Timestamp;
import org.junit.Test;

@SuppressWarnings("unused")
public class PDFVerify {

	//@Test
	public void testPDFVerify() {
		
			String filePath = "/";
			List<SignatureInformations> results = new ArrayList<SignatureInformations>();			
			PDDocument document;
			try {
				document = PDDocument.load(new File(filePath));
				List<SignatureInformations> result = null;

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

					
					// Cache LCR
					Configuration configlcr = Configuration.getInstance();
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
					byte[] assinatura =contents.getBytes();
					/*
					 *  gravar a assinatura em um arquivo separado
					 
				*/	
					  
					File file = new File(filePath + "_.p7s");
					FileOutputStream os = new FileOutputStream(file);
					os.write(assinatura);
					os.flush();
					os.close();
				
					System.out.println("validando");
					result = checker.checkDetachedSignature(buf, assinatura);
					
					
					if (result == null || result.isEmpty()) {
						System.err.println("Erro ao validar");
						//Erro
					}
					results.addAll(checker.getSignaturesInfo());
				}
			
			if (!results.isEmpty()){
				for (SignatureInformations sis : results){
					for (String valErr : sis.getValidatorErrors()){
						System.err.println( "++++++++++++++ ERROS ++++++++++++++++++");
						System.err.println(valErr);
					}
					
					for (String valWarn : sis.getValidatorWarnins()) {
						System.err.println("++++++++++++++ AVISOS ++++++++++++++++++");
						System.err.println(valWarn);
					}

					if (sis.getSignaturePolicy() != null){
						System.out.println("------ Politica ----------------- ");
						System.out.println(sis.getSignaturePolicy().toString());
						
					}
					
					BasicCertificate bc = sis.getIcpBrasilcertificate();
					System.out.println(bc.toString()); 
						if (bc.hasCertificatePF()){
							System.out.println(bc.getICPBRCertificatePF().getCPF());
						}
						if (bc.hasCertificatePJ()){
							System.out.println(bc.getICPBRCertificatePJ().getCNPJ());
							System.out.println(bc.getICPBRCertificatePJ().getResponsibleCPF());
						}
						
					if(sis.getTimeStampSigner()!= null) {
						System.out.println(sis.getTimeStampSigner().toString());
					}
						
					
				}			
				assertTrue(true);
			}else{
				assertTrue(false);
			}
			
			
		} catch (Exception e) {
			e.printStackTrace();
			if (!results.isEmpty()){
				for (SignatureInformations sis : results){
					for (String valErr : sis.getValidatorErrors()){
						System.out.println( "++++++++++++++ ERROS ++++++++++++++++++");
						System.out.println(valErr);
					}
					for (String valWarn : sis.getValidatorWarnins()) {
						System.err.println("++++++++++++++ AVISOS ++++++++++++++++++");
						System.err.println(valWarn);
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
					
					BasicCertificate bc = sis.getIcpBrasilcertificate();
						if (bc.hasCertificatePF()){
							System.out.println(bc.getICPBRCertificatePF().getCPF());
						}
						if (bc.hasCertificatePJ()){
							System.out.println(bc.getICPBRCertificatePJ().getCNPJ());
							System.out.println(bc.getICPBRCertificatePJ().getResponsibleCPF());
						}					 
					
				}			
				assertTrue(true);
			}else{
				assertTrue(false);
			}
		}
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
					FileInputStream fis = new FileInputStream(filePath);
					byte[] buf = null;

					try {
						buf = sig.getSignedContent(fis);
					} finally {
						fis.close();
					}

					CAdESTimeStampSigner varCAdESTimeStampSigner = new CAdESTimeStampSigner();
					varTimeStamp = varCAdESTimeStampSigner.checkTimeStampPDFWithContent(contents.getBytes(), buf);
				}
			if (varTimeStamp != null){
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


