package org.demoiselle.signer.agent.desktop.ui.pdf;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.demoiselle.signer.signature.cades.SignerAlgorithmEnum;
import org.demoiselle.signer.signature.cades.factory.PKCS7Factory;
import org.demoiselle.signer.signature.cades.pkcs7.PKCS7Signer;
import org.demoiselle.signer.signature.core.ca.manager.CAManager;
import org.demoiselle.signer.signature.policy.engine.factory.PolicyFactory.Policies;


public class SignerPDF {
	
	private FileInputStream fis;

	public void doSigner(String originalFile, String signedFile, String signFile) throws Throwable {
		File file = new File(signFile);
		fis = new FileInputStream(file);
		byte[] sign = new byte[(int)file.length()];
		fis.read(sign);
		this.doSigner(originalFile, signedFile, sign);
	}
	
	public void doSigner(String originalFile, String signedFile, byte[] sign) throws Throwable {
		PDDocument original = PDDocument.load(new File(originalFile));
		FileOutputStream fos = new FileOutputStream(new File(signedFile));
		PDSignature signature = new PDSignature();
		signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
		signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
		signature.setSignDate(Calendar.getInstance());
		original.addSignature(signature);
		ExternalSigningSupport externalSigning = original.saveIncrementalForExternalSigning(fos);
		externalSigning.setSignature(sign);
		original.saveIncremental(fos);
		original.close();
	}
	
	public void doSigner(String originalFile, String signedFile, final Certificate certificate, final PrivateKey privateKey) throws Throwable {
		PDDocument original = PDDocument.load(new File(originalFile));
		FileOutputStream fos = new FileOutputStream(new File(signedFile));
		PDSignature signature = new PDSignature();
		signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
		signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
		signature.setSignDate(Calendar.getInstance());
		original.addSignature(signature, new SignatureInterface() {
			public byte[] sign(InputStream contentToSign) throws IOException {
				ByteArrayOutputStream buffer = new ByteArrayOutputStream();
				int nRead;
				byte[] data = new byte[16384];
				while ((nRead = contentToSign.read(data, 0, data.length)) != -1)
				  buffer.write(data, 0, nRead);
				buffer.flush();
				byte[] content = buffer.toByteArray();		
				try {
					Certificate[] chain = CAManager.getInstance().getCertificateChainArray((X509Certificate)certificate);
					PKCS7Signer signer = PKCS7Factory.getInstance().factory();
					signer.setAlgorithm(SignerAlgorithmEnum.SHA512withRSA);
					signer.setSignaturePolicy(Policies.AD_RA_CADES_2_2);
					signer.setPrivateKey(privateKey);
					signer.setCertificates(chain);
					byte[] assinatura = signer.doDetachedSign(content);
					return assinatura;
				} catch (Throwable error) {
					error.printStackTrace();
					return null;
				}
			}
		});
		original.saveIncremental(fos);
		original.close();
	}
	
}
