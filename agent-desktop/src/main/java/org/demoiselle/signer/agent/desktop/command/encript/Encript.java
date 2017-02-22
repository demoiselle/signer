package org.demoiselle.signer.agent.desktop.command.encript;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;

import org.demoiselle.signer.agent.desktop.command.AbstractCommand;
import org.demoiselle.signer.agent.desktop.command.cert.Certificate;
import org.demoiselle.signer.agent.desktop.web.Execute;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.factory.KeyStoreLoaderFactory;
import org.demoiselle.signer.core.util.Base64Utils;

import com.sun.security.auth.callback.DialogCallbackHandler;

@SuppressWarnings("restriction")
public class Encript extends AbstractCommand<EncriptRequest, EncriptResponse> {

	@SuppressWarnings("deprecation")
	public EncriptResponse doCommand(final EncriptRequest data) {
		KeyStoreLoader loader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
		loader.setCallbackHandler(new DialogCallbackHandler());
		KeyStore keyStore = loader.getKeyStore();
		try {
			X509Certificate cert = (X509Certificate)keyStore.getCertificate(data.getAlias());
	        final Cipher cipherEnc = Cipher.getInstance(data.getAlgorithm());
	        PrivateKey privateKey = (PrivateKey) keyStore.getKey(data.getAlias(), null);        
	        cipherEnc.init(Cipher.ENCRYPT_MODE, privateKey);
	        byte[] cript = cipherEnc.doFinal(this.getBytes(data));
	        String encripted = Base64Utils.base64Encode(cript);
	        EncriptResponse result = new EncriptResponse();
	        result.setRequestId(data.getId());
	        result.setEncripted(encripted);
	        Certificate by = new Certificate();
	        by.setAlias(data.getAlias());
	        by.setProvider(keyStore.getProvider().getName());
	        by.setSubject(cert.getSubjectDN().getName());
	        by.setNotAfter(cert.getNotAfter().toGMTString());
	        by.setNotBefore(cert.getNotBefore().toGMTString());
			result.setBy(by);
			result.setPublicKey(Base64Utils.base64Encode(cert.getPublicKey().getEncoded()));
			return result;
		} catch (Throwable error) {
			throw new RuntimeException(error.getMessage(), error);
		}
	}
	
	private byte[] getBytes(EncriptRequest data) {
		return data.getContent().getBytes();
	}

	public static void main(String[] args) {
		EncriptRequest request = new EncriptRequest();
		request.setAlias("(1288991) JOSE RENE NERY CAILLERET CAMPANARIO");
		request.setCompacted(false);
		request.setProvider("SunPKCS11-TokenOuSmartCard_30");
		request.setContent("HELLO WORLD!");
		System.out.println((new Execute()).executeCommand(request));
		
	}
	
}
