package org.demoiselle.signer.policy.impl.cades.pkcs7.impl;

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.KeyStore.Builder;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.Enumeration;

import org.apache.commons.codec.binary.Base64;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.factory.KeyStoreLoaderFactory;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS7Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;
import org.junit.Test;


public class PDFSigner {

	@Test
	public void test() {
		
		String filePDFAssinado = "/home/.pdf";
		String imgPDF = "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MCBvYmoKPDwvSVRYVCgyLjEuNykvVHlwZS9QYWdlcy9Db3VudCAxL0tpZHNbNiAwIFJdPj4KZW5kb2JqCjcgMCBvYmoKPDwvVHlwZS9DYXRhbG9nL1BhZ2VzIDUgMCBSPj4KZW5kb2JqCjggMCBvYmoKPDwvUHJvZHVjZXIoaVRleHQgMi4xLjcgYnkgMVQzWFQpL01vZERhdGUoRDoyMDE3MTAzMDA5NDkxOC0wMicwMCcpL0NyZWF0aW9uRGF0ZShEOjIwMTcxMDMwMDk0OTE4LTAyJzAwJyk+PgplbmRvYmoKeHJlZgowIDkKMDAwMDAwMDAwMCA2NTUzNSBmIAowMDAwMDAwMDE1IDAwMDAwIG4gCjAwMDAwMDQzMTcgMDAwMDAgbiAKMDAwMDAwNDQxMCAwMDAwMCBuIAowMDAwMDAzNTE2IDAwMDAwIG4gCjAwMDAwMDQ0OTggMDAwMDAgbiAKMDAwMDAwNDEyOCAwMDAwMCBuIAowMDAwMDA0NTYxIDAwMDAwIG4gCjAwMDAwMDQ2MDYgMDAwMDAgbiAKdHJhaWxlcgo8PC9Sb290IDcgMCBSL0lEIFs8ZTE4NDQwM2JhY2FhNDVlMDAzYzEwNzY0M2E1OTk0Yjg+PGQwMGY0YTA3ZGQ2MjI2NmMyMTBmNDY0MDVhMTdjMjFhPl0vSW5mbyA4IDAgUi9TaXplIDk+PgpzdGFydHhyZWYKNDcyOAolJUVPRgo=";
		
		try {
				this.doSigner(imgPDF, filePDFAssinado);
		} catch (Throwable e) {
			e.printStackTrace();
			assertTrue(false);
		}		
		assertTrue(true);
	}
	
	private void doSigner(String imgPDF, final String signedFile) throws Throwable {
			
			ByteArrayInputStream target = new ByteArrayInputStream(Base64.decodeBase64(imgPDF));
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			Long documentId = Long.parseLong("300");
			byte[] buf = new byte[1024];
			int n = 0;

			while ((n = target.read(buf)) >= 0) {
				baos.write(buf, 0, n);
			}
			byte[] bytes = baos.toByteArray();			
			InputStream contentForPDF = null;
			
			contentForPDF = new ByteArrayInputStream(bytes);
			
			PDDocument original = PDDocument.load(contentForPDF);
						
			FileOutputStream fos = new FileOutputStream(new File(signedFile));
			PDSignature signature = new PDSignature();
			signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
			signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
			Calendar calendar =Calendar.getInstance();
			calendar.set(2017, Calendar.NOVEMBER, 6, 11, 25,30);
			signature.setSignDate(calendar);
			original.setDocumentId(documentId);
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
						java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
	                	String contentEncoded = Base64.encodeBase64String(content);	                	
	                	System.out.println(contentEncoded);	                	
	                    byte[] hash = md.digest(content);	                    
	                    String hashEncoded = new String(Base64.encodeBase64(hash));	                    
	                    System.out.println(hashEncoded);

	                    KeyStore ks = getKeyStoreToken();
	                    String alias = getAlias(ks);
	                    
	                    PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
	        			signer.setCertificates(ks.getCertificateChain(alias));

	        			// para token
	        			signer.setPrivateKey((PrivateKey) ks.getKey(alias, null));

	        			// politica sem carimbo de tempo
	        			signer.setSignaturePolicy(PolicyFactory.Policies.AD_RB_CADES_2_2);
	        			// com carimbo de tempo
	        			//signer.setSignaturePolicy(PolicyFactory.Policies.AD_RT_CADES_2_2);
	        			//signer.setSignaturePolicy(PolicyFactory.Policies.AD_RB_PADES_1_0);

	        			// para mudar o algoritimo
	        			signer.setAlgorithm(SignerAlgorithmEnum.SHA256withRSA);
	                    
						byte [] assinatura =signer.doHashSign(hash);
						
						
//						File file = new File("/home/.p7s");
//						FileOutputStream os = new FileOutputStream(file);
//						os.write(assinatura);
//						os.flush();
//						os.close();
						
						
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
		

	// Usa o Signer para leitura, funciona para windows e NeoID
	@SuppressWarnings("unused")
	private KeyStore getKeyStoreTokenBySigner() {

		try {
			
			KeyStoreLoader keyStoreLoader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
			KeyStore keyStore = keyStoreLoader.getKeyStore();

			return keyStore;

		} catch (Exception e1) {
			e1.printStackTrace();
			return null;
		} finally {
		}

	}
	
	
	/**
	 * 
	 * Faz a leitura do token em LINUX, precisa setar a lib (.SO) e a senha do token.
	 */
	@SuppressWarnings("restriction")
	private KeyStore getKeyStoreToken() {

		try {
			// ATENÇÃO ALTERAR CONFIGURAÇÃO ABAIXO CONFORME O TOKEN USADO

			// Para TOKEN Branco a linha abaixo
			// String pkcs11LibraryPath =
			// "/usr/lib/watchdata/ICP/lib/libwdpkcs_icp.so";

			// Para TOKEN Azul a linha abaixo
			String pkcs11LibraryPath = "/usr/lib/libeToken.so";

			StringBuilder buf = new StringBuilder();
			buf.append("library = ").append(pkcs11LibraryPath).append("\nname = Provedor\n");
			Provider p = new sun.security.pkcs11.SunPKCS11(new ByteArrayInputStream(buf.toString().getBytes()));
			Security.addProvider(p);
			// ATENÇÃO ALTERAR "SENHA" ABAIXO
			Builder builder = KeyStore.Builder.newInstance("PKCS11", p,	new KeyStore.PasswordProtection("senha".toCharArray()));
			KeyStore ks;
			ks = builder.getKeyStore();

			return ks;

		} catch (Exception e1) {
			e1.printStackTrace();
			return null;
		} finally {
		}

	}
	
	
	
	private String getAlias(KeyStore ks) {
		@SuppressWarnings("unused")
		Certificate[] certificates = null;
		String alias = "";
		Enumeration<String> e;
		try {
			e = ks.aliases();
			while (e.hasMoreElements()) {
				alias = e.nextElement();
				System.out.println("alias..............: " + alias);
				System.out.println("iskeyEntry"+ ks.isKeyEntry(alias));
				System.out.println("containsAlias"+ks.containsAlias(alias));
				//System.out.println(""+ks.getKey(alias, null));
				certificates = ks.getCertificateChain(alias);
			}

		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return alias;
	}
	
}