package org.demoiselle.signer.policy.impl.cades.pkcs1.impl;

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import org.apache.commons.codec.binary.Base64;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.junit.Test;

public class PKCS1CheckTest {

	//@Test
	public void testCheck() throws CertificateException, NoSuchProviderException {
		PKCS1SignerImpl pkcs1 = new PKCS1SignerImpl();
		
		String fileToVerifyDirName = "";
		String fileSignature = "";
		byte[] content = readContent(fileToVerifyDirName); 
		//String signatureBase64 ="IJy/ikXAVp/U2dQWlWZKZi1o0nI9ycRpJPq1utap1oUgBAAFAQIEA2UBSIZgCQYNMDEw";
		//byte[] signature = Base64.decodeBase64(signatureBase64);
		byte[] signature =  readContent(fileSignature);
		String certicateSigner = "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";
		byte[] certificateByte = Base64.decodeBase64(certicateSigner);
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
		Certificate cert = cf.generateCertificate(new ByteArrayInputStream(certificateByte));
		pkcs1.setPublicKey(cert.getPublicKey());
		pkcs1.setAlgorithm(SignerAlgorithmEnum.SHA256withRSA);
		assertTrue(pkcs1.check(content, signature));
		
	}
	
	
	private byte[] readContent(String parmFile) {
		byte[] result = null;
		try {
			File file = new File(parmFile);
			FileInputStream is = new FileInputStream(parmFile);
			result = new byte[(int) file.length()];
			is.read(result);
			is.close();
		} catch (IOException ex) {
			ex.printStackTrace();
		}
		return result;
	}
	
}
