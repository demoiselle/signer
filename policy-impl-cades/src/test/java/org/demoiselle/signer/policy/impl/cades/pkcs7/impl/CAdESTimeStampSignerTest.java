package org.demoiselle.signer.policy.impl.cades.pkcs7.impl;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStore.Builder;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;

import org.demoiselle.signer.core.keystore.loader.implementation.MSKeyStoreLoader;
import org.demoiselle.signer.cryptography.DigestAlgorithmEnum;
import org.demoiselle.signer.timestamp.Timestamp;
import org.junit.Test;

@SuppressWarnings("unused")
public class CAdESTimeStampSignerTest {

	// TESTES COMENTADOS PARA BUILD
	
	//@Test
	public void testDoTimeStampForSignature() {
		String fileSignatureDirName = "local_e_nome_do_arquivo_da_assinatura";
						
		try {
			
			// Para certificado em Token
			KeyStore ks = getKeyStoreToken();

			// Para certificados no so windows (mascapi)
			// KeyStore ks = getKeyStoreOnWindows();
			
			// Para certificado em arquivo A1
			// KeyStore ks = getKeyStoreFile();

			// quando certificado em arquivo, precisa informar a senha
			//char[] senha = "senha".toCharArray();

			String alias = getAlias(ks);
			
			byte[] signatureFile = readContent(fileSignatureDirName);
			CAdESTimeStampSigner varCAdESTimeStampSigner = new CAdESTimeStampSigner();

			varCAdESTimeStampSigner.setCertificates(ks.getCertificateChain(alias));

			// para token
			varCAdESTimeStampSigner.setPrivateKey((PrivateKey) ks.getKey(alias, null));

			// para arquivo
			// signer.setPrivateKey((PrivateKey) ks.getKey(alias, senha));
			
			byte[] signatureWithTimeStamp = varCAdESTimeStampSigner
					.doTimeStampForSignature(signatureFile);

			File file = new File(fileSignatureDirName + ".timestamp" + ".p7s");
			FileOutputStream os = new FileOutputStream(file);
			os.write(signatureWithTimeStamp);
			os.flush();
			os.close();
			assertTrue(true);

		} catch (Exception ex) {
			ex.printStackTrace();
			assertTrue(false);
		}

	}

	//@Test
	public void testDoTimeStampForContent() {
		String fileDirName = "caminho do arquivo";
				
		try {
			
			// Para certificado em Token
			KeyStore ks = getKeyStoreToken();

			// Para certificados no so windows (mascapi)
			// KeyStore ks = getKeyStoreOnWindows();
			
			
			// Para certificado em arquivo A1
			// KeyStore ks = getKeyStoreFile();			

			// quando certificado em arquivo, precisa informar a senha
			//char[] senha = "senha".toCharArray();


			String alias = getAlias(ks);
			
			byte[] content = readContent(fileDirName);
			CAdESTimeStampSigner varCAdESTimeStampSigner = new CAdESTimeStampSigner();

			varCAdESTimeStampSigner.setCertificates(ks.getCertificateChain(alias));

			// para token
			varCAdESTimeStampSigner.setPrivateKey((PrivateKey) ks.getKey(alias, null));

			// para arquivo
			// signer.setPrivateKey((PrivateKey) ks.getKey(alias, senha));
			
			byte[] timeStampForContent = varCAdESTimeStampSigner.doTimeStampForContent(content);

			File file = new File(fileDirName + "junit.timestamp.p7s");
			FileOutputStream os = new FileOutputStream(file);
			os.write(timeStampForContent);
			os.flush();
			os.close();
			assertTrue(true);

		} catch (Exception ex) {
			ex.printStackTrace();
			assertTrue(false);
		}

	}

	//@Test
	public void testDoTimeStampForHashContent() {
		String fileDirName = "local_e_nome_do_arquivo";
		
		try {
			
			// Para certificado em Token
			KeyStore ks = getKeyStoreToken();

			// Para certificados no so windows (mascapi)
			// KeyStore ks = getKeyStoreOnWindows();
			
			// Para certificado em arquivo A1
			// KeyStore ks = getKeyStoreFile();			

			// quando certificado em arquivo, precisa informar a senha
			//char[] senha = "senha".toCharArray();


			String alias = getAlias(ks);
			
			byte[] content = readContent(fileDirName);
			
			
			// gera o hash do conteudo
			java.security.MessageDigest md = java.security.MessageDigest
					.getInstance(DigestAlgorithmEnum.SHA_256.getAlgorithm());
			byte[] hash = md.digest(content);
			
			CAdESTimeStampSigner varCAdESTimeStampSigner = new CAdESTimeStampSigner();

			varCAdESTimeStampSigner.setCertificates(ks.getCertificateChain(alias));

			// para token
			varCAdESTimeStampSigner.setPrivateKey((PrivateKey) ks.getKey(alias, null));

			// para arquivo
			// signer.setPrivateKey((PrivateKey) ks.getKey(alias, senha));
			
			byte[] timeStampForContent = varCAdESTimeStampSigner.doTimeStampFromHashContent(hash);

			File file = new File(fileDirName +"_fromHash"+ ".timestamp.p7s");
			FileOutputStream os = new FileOutputStream(file);
			os.write(timeStampForContent);
			os.flush();
			os.close();
			assertTrue(true);

		} catch (Exception ex) {
			ex.printStackTrace();
			assertTrue(false);
		}
	}

	// @Test
	public void testCheckTimeStampOnSignature() {
		String fileSignatureDirName = "/";
		

		
		
		try {
			byte[] signatureFile = readContent(fileSignatureDirName);
			CAdESTimeStampSigner varCAdESTimeStampSigner = new CAdESTimeStampSigner();
			List<Timestamp> listTimeStamp = varCAdESTimeStampSigner.checkTimeStampOnSignature(signatureFile);
			if (!listTimeStamp.isEmpty()){
				for (Timestamp ts : listTimeStamp){
					System.out.println(ts.toString());
					assertTrue(true);
				}
			}else{
				assertTrue(false);
			}
				
		} catch (Exception ex) {
			ex.printStackTrace();
			assertTrue(false);
		}		

	}

	//@Test
	public void testCheckTimeStampWithContent() {
		String fileTimeStampDirName = "/home/signer/eclipse-workspace-teste/serpro-test/src/main/resources/mail_bytearray.timestamp.p7s";
		String fileContentDirName = "/home/signer/eclipse-workspace-teste/serpro-test/src/main/resources/mail_bytearray";
		

		

		
		try {
			byte[] timeStampFile = readContent(fileTimeStampDirName);
			byte[] content = readContent(fileContentDirName);
			CAdESTimeStampSigner varCAdESTimeStampSigner = new CAdESTimeStampSigner();
			Timestamp varTimeStamp = varCAdESTimeStampSigner.checkTimeStampWithContent(timeStampFile, content);
			if (varTimeStamp != null){
				System.out.println(varTimeStamp.toString());
				assertTrue(true);
			}else{
				assertTrue(false);
			}			
		} catch (Exception ex) {
			ex.printStackTrace();
			assertTrue(false);						
		}
	}
	
	//@Test
	public void testCheckTimeStampWithHash() {
		String fileTimeStampDirName = "local_e_nome_do_arquivo_da_assinatura";
		String fileContentDirName = "local_e_nome_do_arquivo_assinado";
		try {
			byte[] timeStampFile = readContent(fileTimeStampDirName);
			byte[] content = readContent(fileContentDirName);
			// gera o hash do conteudo
			java.security.MessageDigest md = java.security.MessageDigest
					.getInstance(DigestAlgorithmEnum.SHA_256.getAlgorithm());
			byte[] hash = md.digest(content);
			CAdESTimeStampSigner varCAdESTimeStampSigner = new CAdESTimeStampSigner();
			Timestamp varTimeStamp = varCAdESTimeStampSigner.checkTimeStampWithHash(timeStampFile, hash);
			if (varTimeStamp != null){
				System.out.println(varTimeStamp.toString());
				assertTrue(true);
			}else{
				assertTrue(false);
			}
		} catch (Exception ex) {
			ex.printStackTrace();
			assertTrue(false);
		}
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
		}

	}

	/**
	 * 
	 * Faz a leitura do certificado armazenado em arquivo (A1)
	 */

	private KeyStore getKeyStoreFile() {

		try {
			KeyStore ks = KeyStore.getInstance("pkcs12");

			// Alterar a senha
			char[] senha = "senha".toCharArray();

			// informar onde esta o arquivo
			InputStream ksIs = new FileInputStream("/home/{usuario}/xx.p12");
			ks.load(ksIs, senha);

			KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			kmf.init(ks, senha);

			return ks;

		} catch (Exception e1) {
			e1.printStackTrace();
			return null;
		}

	}

	/**
	 * 
	 * Keytore a partir de MSCAPI
	 */

	private KeyStore getKeyStoreOnWindows() {

		try {
			
			MSKeyStoreLoader msKeyStoreLoader = new MSKeyStoreLoader();
			
			KeyStore ks = msKeyStoreLoader.getKeyStore();

			return ks;

		} catch (Exception e1) {
			e1.printStackTrace();
			return null;
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
				System.out.println("alias..............: {}" + alias);
				certificates = ks.getCertificateChain(alias);
			}

		} catch (KeyStoreException e1) {
			e1.printStackTrace();
		}
		X509Certificate c = (X509Certificate) certificates[0];
		System.out.println("Número de série....: {}" + c.getSerialNumber().toString());
		return alias;
	}

}
