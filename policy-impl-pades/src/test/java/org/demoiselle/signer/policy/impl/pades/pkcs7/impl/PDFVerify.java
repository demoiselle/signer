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
	public void test() {
		
	
			String filePath = "/home/...";
			
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
					result = checker.checkDetachedSignature(buf, contents.getBytes());
					if (result == null || result.isEmpty()) {
						System.out.println("Erro ao validar");
						//Erro
					}
					results.addAll(checker.getSignaturesInfo());
				}
			
			if (!results.isEmpty()){
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
					
					BasicCertificate bc = sis.getSignerBasicCertificate();
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
			
			
		} catch (Exception e) {
			e.printStackTrace();
			if (!results.isEmpty()){
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
					
					BasicCertificate bc = sis.getSignerBasicCertificate();
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
	
	

    public void testValidateSignatureVlidationTestAdbePkcs7Sha1() throws Exception
    {
        String filePath = "caminho arquivo";
        
        byte[] pdfByte;
        PDDocument pdfDoc = null;
        SignerInformationVerifier verifier = null;
        try
        {
            //pdfByte = IOUtils.toByteArray(this.getClass().getResourceAsStream("Teste_AI_Assinado_Assinador_Livre.pdf"));
            pdfDoc = PDDocument.load(new File(filePath));
            PDSignature signature = pdfDoc.getSignatureDictionaries().get(0);
            byte[] signedContentAsBytes = signature.getSignedContent(new FileInputStream(filePath));

            byte[] signatureAsBytes = signature.getContents(new FileInputStream(filePath));
            
            PAdESChecker checker = new PAdESChecker();
            checker.checkDetachedSignature(signedContentAsBytes, signatureAsBytes);
                        
            CMSSignedData cms = new CMSSignedData(new ByteArrayInputStream(signatureAsBytes));
                        
            SignerInformation signerInfo = (SignerInformation) cms.getSignerInfos().getSigners().iterator().next();
            @SuppressWarnings("unchecked")
			X509CertificateHolder cert = (X509CertificateHolder) cms.getCertificates().getMatches(signerInfo.getSID())
                    .iterator().next();
            verifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider(new BouncyCastleProvider()).build(cert);

            boolean verifyRt = signerInfo.verify(verifier);
            System.out.println("Verify result: " + verifyRt);

            
            MessageDigest md = MessageDigest.getInstance("SHA1");
            byte[] calculatedDigest = md.digest(signedContentAsBytes);
            byte[] signedDigest = (byte[]) cms.getSignedContent().getContent();
            System.out.println("Document digest equals: " + Arrays.equals(calculatedDigest, signedDigest));
            
            
        		
			
        }
        finally
        {
            if (pdfDoc != null)
            {
                pdfDoc.close();
            }
        }
    }
	
}


