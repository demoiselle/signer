package org.demoiselle.signer.policy.impl.pades.pkcs7.impl;

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.KeyStore.Builder;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.Enumeration;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.factory.KeyStoreLoaderFactory;
import org.demoiselle.signer.cryptography.DigestAlgorithmEnum;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.junit.Test;


@SuppressWarnings("unused")
public class PDFSignerTest {

	/**
	 *  A partir de um arquivo gera um pdf assinado
	 */
	//@Test
	public void testComFile() {
		
		// INFORMAR o arquivo de entrada
		//
		//String fileDirName = "C:\\Users\\{usuario}\\arquivo_assinar";
		String fileDirName = "/";
		byte[] fileToSign = readContent(fileDirName);

		// INFORMAR o nome do arquivo de saida assinado
		//
		//String fileDirName = "C:\\Users\\{usuario}\\arquivo_assinado";

		String filePDFAssinado = "/";
		
		try {
				this.doSigner(fileToSign, filePDFAssinado);
		} catch (Throwable e) {
			e.printStackTrace();
			assertTrue(false);
		}		
		assertTrue(true);
	}

	
	/**
	 *  A partir de uma string base64 com o conteúdo do PDF gera um arquivo PDF Assinado
	 */
	@Test
	public void testComBase64() {
		
		// INFORMAR o nome do arquivo de saida assinado
		//
		//String fileDirName = "C:\\Users\\{usuario}\\arquivo_assinado";

		String filePDFAssinado = "/home/signer/Documentos/00NeoSigner/assinado-ts.pdf";
		
		String imgPDF="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Nzk1MjhdL0dyb3VwPDwvUy9UcmFuc3BhcmVuY3kvQ1MvRGV2aWNlUkdCL0kgdHJ1ZT4+L0NvbnRlbnRzIDIgMCBSPj4KZW5kb2JqCgo0IDAgb2JqCjw8L1R5cGUvUGFnZXMKL1Jlc291cmNlcyAxMSAwIFIKL01lZGlhQm94WyAwIDAgNTk1IDg0MSBdCi9LaWRzWyAxIDAgUiBdCi9Db3VudCAxPj4KZW5kb2JqCgoxMiAwIG9iago8PC9UeXBlL0NhdGFsb2cvUGFnZXMgNCAwIFIKL1BhZ2VNb2RlL1VzZU91dGxpbmVzCi9PcGVuQWN0aW9uWzEgMCBSIC9YWVogbnVsbCBudWxsIDBdCi9MYW5nKHB0LUJSKQo+PgplbmRvYmoKCjEzIDAgb2JqCjw8L0NyZWF0b3I8RkVGRjAwNTcwMDcyMDA2OTAwNzQwMDY1MDA3Mj4KL1Byb2R1Y2VyPEZFRkYwMDRDMDA2OTAwNjIwMDcyMDA2NTAwNEYwMDY2MDA2NjAwNjkwMDYzMDA2NTAwMjAwMDM2MDAyRTAwMzQ+Ci9DcmVhdGlvbkRhdGUoRDoyMDIxMDMyNTE2MjUwMi0wMycwMCcpPj4KZW5kb2JqCgp4cmVmCjAgMTQKMDAwMDAwMDAwMCA2NTUzNSBmIAowMDAwMDA3MTA4IDAwMDAwIG4gCjAwMDAwMDAwMTkgMDAwMDAgbiAKMDAwMDAwMDI1OSAwMDAwMCBuIAowMDAwMDA3Mjc3IDAwMDAwIG4gCjAwMDAwMDAyNzkgMDAwMDAgbiAKMDAwMDAwNjI0MSAwMDAwMCBuIAowMDAwMDA2MjYyIDAwMDAwIG4gCjAwMDAwMDY0NTcgMDAwMDAgbiAKMDAwMDAwNjgwOSAwMDAwMCBuIAowMDAwMDA3MDIxIDAwMDAwIG4gCjAwMDAwMDcwNTMgMDAwMDAgbiAKMDAwMDAwNzM3NiAwMDAwMCBuIAowMDAwMDA3NDk1IDAwMDAwIG4gCnRyYWlsZXIKPDwvU2l6ZSAxNC9Sb290IDEyIDAgUgovSW5mbyAxMyAwIFIKL0lEIFsgPEMwQzQyM0FBREZFOEI0ODgyMUQwQUQ4MUE3Q0EyRDIwPgo8QzBDNDIzQUFERkU4QjQ4ODIxRDBBRDgxQTdDQTJEMjA+IF0KL0RvY0NoZWNrc3VtIC9GRTAzQjYzNUUwRUYxMDczMjZERDNERUQ2NjhGRkI4RQo+PgpzdGFydHhyZWYKNzY3MAolJUVPRgo=";
		
		try {
				byte[] toSign = Base64.decodeBase64(imgPDF);
				this.doSigner(toSign, filePDFAssinado);
		} catch (Throwable e) {
			e.printStackTrace();
			assertTrue(false);
		}		
		assertTrue(true);
	}
	
	/**
	 * A partir de uma string base64 com o conteúdo do PDF gera um arquivo PDF Assinado
	 * Neste teste:
	 * - primeiro gera o Hash do arquivo a ser assinado
	 * - segundo assina o Hash
	 * - terceiro anexa a Assinatura no Arquivo.
	 */
	//@Test
	public void testComBase64TresEtapas() {
		

		String filePDFAssinado = "/home/signer/Documentos/00NeoSigner/novo_assinado.pdf";
		String imgPDF="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Nzk1MjhdL0dyb3VwPDwvUy9UcmFuc3BhcmVuY3kvQ1MvRGV2aWNlUkdCL0kgdHJ1ZT4+L0NvbnRlbnRzIDIgMCBSPj4KZW5kb2JqCgo0IDAgb2JqCjw8L1R5cGUvUGFnZXMKL1Jlc291cmNlcyAxMSAwIFIKL01lZGlhQm94WyAwIDAgNTk1IDg0MSBdCi9LaWRzWyAxIDAgUiBdCi9Db3VudCAxPj4KZW5kb2JqCgoxMiAwIG9iago8PC9UeXBlL0NhdGFsb2cvUGFnZXMgNCAwIFIKL1BhZ2VNb2RlL1VzZU91dGxpbmVzCi9PcGVuQWN0aW9uWzEgMCBSIC9YWVogbnVsbCBudWxsIDBdCi9MYW5nKHB0LUJSKQo+PgplbmRvYmoKCjEzIDAgb2JqCjw8L0NyZWF0b3I8RkVGRjAwNTcwMDcyMDA2OTAwNzQwMDY1MDA3Mj4KL1Byb2R1Y2VyPEZFRkYwMDRDMDA2OTAwNjIwMDcyMDA2NTAwNEYwMDY2MDA2NjAwNjkwMDYzMDA2NTAwMjAwMDM2MDAyRTAwMzQ+Ci9DcmVhdGlvbkRhdGUoRDoyMDIxMDMyNTE2MjUwMi0wMycwMCcpPj4KZW5kb2JqCgp4cmVmCjAgMTQKMDAwMDAwMDAwMCA2NTUzNSBmIAowMDAwMDA3MTA4IDAwMDAwIG4gCjAwMDAwMDAwMTkgMDAwMDAgbiAKMDAwMDAwMDI1OSAwMDAwMCBuIAowMDAwMDA3Mjc3IDAwMDAwIG4gCjAwMDAwMDAyNzkgMDAwMDAgbiAKMDAwMDAwNjI0MSAwMDAwMCBuIAowMDAwMDA2MjYyIDAwMDAwIG4gCjAwMDAwMDY0NTcgMDAwMDAgbiAKMDAwMDAwNjgwOSAwMDAwMCBuIAowMDAwMDA3MDIxIDAwMDAwIG4gCjAwMDAwMDcwNTMgMDAwMDAgbiAKMDAwMDAwNzM3NiAwMDAwMCBuIAowMDAwMDA3NDk1IDAwMDAwIG4gCnRyYWlsZXIKPDwvU2l6ZSAxNC9Sb290IDEyIDAgUgovSW5mbyAxMyAwIFIKL0lEIFsgPEMwQzQyM0FBREZFOEI0ODgyMUQwQUQ4MUE3Q0EyRDIwPgo8QzBDNDIzQUFERkU4QjQ4ODIxRDBBRDgxQTdDQTJEMjA+IF0KL0RvY0NoZWNrc3VtIC9GRTAzQjYzNUUwRUYxMDczMjZERDNERUQ2NjhGRkI4RQo+PgpzdGFydHhyZWYKNzY3MAolJUVPRgo=";
		
		try {
				byte[] toSign = Base64.decodeBase64(imgPDF);
				
				byte[] hashToSign = this.doHash(toSign);
				byte[] signature =  signHash (hashToSign);
				addSignature(toSign, signature, filePDFAssinado);
		} catch (Throwable e) {
			e.printStackTrace();
			assertTrue(false);
		}		
		assertTrue(true);
	}
	
	
	private void doSigner(byte[] toSign, final String signedFile) throws Throwable {

			FileOutputStream fos = new FileOutputStream(signedFile);
			java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
			byte[] hashOriginal = md.digest(toSign);	 
			String hashOriginalToHex = org.bouncycastle.util.encoders.Hex.toHexString(hashOriginal);
			BigInteger bigId = new BigInteger(hashOriginalToHex.toUpperCase(),16);
			PDSignature signature = new PDSignature();
			signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
			signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
			PDDocument original = PDDocument.load(toSign);
			original.setDocumentId(bigId.longValue());
			original.addSignature(signature, new SignatureInterface() {
				public byte[] sign(InputStream contentToSign) throws IOException {
					
					byte[] byteContentToSign = IOUtils.toByteArray(contentToSign);
					try {						
						java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-512");
						// gera o hash do arquivo
						// devido a uma restrição do token branco, no windws só funciona com 256
						if (org.demoiselle.signer.core.keystore.loader.configuration.Configuration.getInstance().getSO().toLowerCase().indexOf("indows") > 0) {
							md = java.security.MessageDigest.getInstance(DigestAlgorithmEnum.SHA_256.getAlgorithm());
						}
	                    byte[] hashToSign = md.digest(byteContentToSign);	     
	                    String hashToSignHex = org.bouncycastle.util.encoders.Hex.toHexString(hashToSign);
	                    System.out.println("hashPDFtoSign: "+hashToSignHex);

	                    //windows e NeoID
	                    //KeyStore ks = getKeyStoreTokenBySigner(); 
                    
	                    //KeyStore ks = getKeyStoreToken();
	                    
	                    // para arquivo
	                    KeyStore ks = getKeyStoreFileBySigner();
                    	
	                    // para timeStamp
	                    
	                    KeyStore ksToTS = getKeyStoreTokenBySigner();
	                    
                		String alias = getAlias(ks);
                		
                		String aliasTS = getAlias(ksToTS);
	                    
	                    PAdESSigner signer = new PAdESSigner();
	                    signer.setCertificates(ks.getCertificateChain(alias));
	        			signer.setCertificatesForTimeStamp(ksToTS.getCertificateChain(aliasTS));

	        			// para token
	        			//signer.setPrivateKey((PrivateKey) ks.getKey(alias, null));
	        			
	        			// para arquivo
	        			char[] senhaArquivo = "teste".toCharArray();
	        			signer.setPrivateKey((PrivateKey) ks.getKey(alias, senhaArquivo));

	        			// signer.setSignaturePolicy(PolicyFactory.Policies.AD_RB_PADES_1_1);
	        			// com carimbo de tempo
	        			
	        			signer.setPrivateKeyForTimeStamp((PrivateKey) ksToTS.getKey(aliasTS, null));
	          			signer.setSignaturePolicy(PolicyFactory.Policies.AD_RT_CADES_2_3);
	        			
	        			// para mudar o algoritimo conforme o sistema operacional
	        			// devido a uma restrição do token branco, no windows só funciona com 256
	        			signer.setAlgorithm(SignerAlgorithmEnum.SHA512withRSA);
	        			if (org.demoiselle.signer.core.keystore.loader.configuration.Configuration.getInstance().getSO().toLowerCase().indexOf("indows") > 0) {
	        				signer.setAlgorithm(SignerAlgorithmEnum.SHA256withRSA);
	        			}	        			
	                    
						byte [] assinatura =signer.doHashSign(hashToSign);
						
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
	
	
	
	private byte[] doHash (byte[] toSign) throws NoSuchAlgorithmException, InvalidPasswordException, IOException {
			
			java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
			byte[] hashOriginal = md.digest(toSign);	 
			String hashOriginalToHex = org.bouncycastle.util.encoders.Hex.toHexString(hashOriginal);
			BigInteger bigId = new BigInteger(hashOriginalToHex.toUpperCase(),16);
			PDSignature signature = new PDSignature();
			signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
			signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
			PDDocument original;
			original = PDDocument.load(toSign);
			original.setDocumentId(bigId.longValue());
			original.addSignature(signature);
			ExternalSigningSupport externalSigningSupport = original.saveIncrementalForExternalSigning(null);
	        InputStream contentToSign = externalSigningSupport.getContent();
	        byte[] byteContentToSign = IOUtils.toByteArray(contentToSign);
	        
	        String StringbyteContentToSign = new String(Base64.encodeBase64(byteContentToSign));
	        System.out.println("StringbyteContentToSign: "+StringbyteContentToSign);
	        md = java.security.MessageDigest.getInstance("SHA-512");
			// devido a uma restrição do token branco, no windws só funciona com 256
			//if (org.demoiselle.signer.core.keystore.loader.configuration.Configuration.getInstance().getSO().toLowerCase().indexOf("indows") > 0) {
				md = java.security.MessageDigest.getInstance(DigestAlgorithmEnum.SHA_256.getAlgorithm());
			//}	        
	        byte[] hashToSign = md.digest(byteContentToSign);	        
            //String hashToSingHex = org.bouncycastle.util.encoders.Hex.toHexString(hashToSign);
            String hashToSignEncoded = new String(Base64.encodeBase64(hashToSign));
            //System.out.println("hashToSignEncoded: "+hashToSignEncoded);
			original.close();
			return hashToSign;
            
		
	}
	
	private byte[] signHash(byte[] hashToSign) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        //windows e NeoID
        KeyStore ks = getKeyStoreTokenBySigner(); 
    
        //KeyStore ks = getKeyStoreToken();
        String alias = getAlias(ks);
        
        PAdESSigner signer = new PAdESSigner();
		signer.setCertificates(ks.getCertificateChain(alias));

		// para token
		signer.setPrivateKey((PrivateKey) ks.getKey(alias, null));
		
		signer.setSignaturePolicy(PolicyFactory.Policies.AD_RB_PADES_1_1);
		// com carimbo de tempo
			//signer.setSignaturePolicy(PolicyFactory.Policies.AD_RT_PADES_1_1);
		
		// para mudar o algoritimo
		// devido a uma restrição do token branco, no windws só funciona com 256		
		//signer.setAlgorithm(SignerAlgorithmEnum.SHA512withRSA);
		//if (org.demoiselle.signer.core.keystore.loader.configuration.Configuration.getInstance().getSO().toLowerCase().indexOf("indows") > 0) {
			signer.setAlgorithm(SignerAlgorithmEnum.SHA256withRSA);
		//}	        			
		
		byte [] assinatura = signer.doHashSign(hashToSign);
		String StringAssinatura = new String(Base64.encodeBase64(assinatura));
		System.out.println(StringAssinatura);
		
		return assinatura;	
		
	}
	
	/**
	 * 
	 * @param toSign
	 * @param signature
	 * @param signedFile
	 * @throws InvalidPasswordException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 */
			
	private void addSignature(byte[] toSign, byte[] signature, final String signedFile) throws InvalidPasswordException, IOException, NoSuchAlgorithmException{
		final byte[] varSignature = signature;
		FileOutputStream fileOut = new FileOutputStream(signedFile);
		java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
		byte[] hashOriginal = md.digest(toSign);	 
		String hashOriginalToHex = org.bouncycastle.util.encoders.Hex.toHexString(hashOriginal);
		BigInteger bigId = new BigInteger(hashOriginalToHex.toUpperCase(),16);
		PDSignature pdfSignature = new PDSignature();
		pdfSignature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
		pdfSignature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
		PDDocument original;
		original = PDDocument.load(toSign);
		original.setDocumentId(bigId.longValue());
	    original.addSignature(pdfSignature);
	    ExternalSigningSupport externalSigningSupport = original.saveIncrementalForExternalSigning(fileOut);
	    externalSigningSupport.setSignature(signature);
	    byte[] bytePdfSigned = Files.readAllBytes(Paths.get(signedFile));
	    String pdfSignedEncoded = new String(Base64.encodeBase64(bytePdfSigned));
	    original.close();
	    fileOut.flush();
	    fileOut.close();
		
	}
	
	
	
	
	private KeyStore getKeyStoreFileBySigner() {

		try {
				// informar o caminho e nome do arquivo
			File filep12 = new File("/home/signer/Documentos/00NeoSigner/pf01.p12");
			
			KeyStoreLoader loader = KeyStoreLoaderFactory.factoryKeyStoreLoader(filep12);
			// Informar a senha
			KeyStore keystore = loader.getKeyStore("teste");
			return keystore;

		} catch (Exception e1) {
			e1.printStackTrace();
			return null;
		} finally {
		}

	}

	
	
	private String getAlias(KeyStore ks) {
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