package org.demoiselle.signer.agent.desktop.command.signer;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.demoiselle.signer.agent.desktop.command.AbstractCommand;
import org.demoiselle.signer.agent.desktop.ui.PinHandler;
import org.demoiselle.signer.agent.desktop.web.Execute;
import org.demoiselle.signer.signature.cades.factory.PKCS7Factory;
import org.demoiselle.signer.signature.cades.pkcs7.PKCS7Signer;
import org.demoiselle.signer.signature.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.signature.core.keystore.loader.factory.KeyStoreLoaderFactory;
import org.demoiselle.signer.signature.core.util.Base64Utils;
import org.demoiselle.signer.signature.policy.engine.factory.PolicyFactory.Policies;

public class FileSigner extends AbstractCommand<SignerRequest, SignerResponse>{

	@Override
	public SignerResponse doCommand(final SignerRequest request) {
		
		KeyStoreLoader loader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
		loader.setCallbackHandler(new PinHandler());
		KeyStore keyStore = loader.getKeyStore();
		try {
			X509Certificate cert = (X509Certificate)keyStore.getCertificate(request.getAlias());
	        PrivateKey privateKey = (PrivateKey) keyStore.getKey(request.getAlias(), null);        
			PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
	        signer.setCertificates(keyStore.getCertificateChain(request.getAlias()));
	        signer.setPrivateKey(privateKey);
	        Policies policie = null;
	        try {
	        	policie = Policies.valueOf(request.getSignaturePolicy());
	        } catch (Throwable error) {
	        	policie = Policies.AD_RB_CADES_2_1;
	        }
	        signer.setSignaturePolicy(policie);
	        signer.setAttached(false);
	        
	        byte[] byteFile = null;
	        SignerResponse result = new SignerResponse();
	        String fileName = new String(this.getContent(request));
	        File file = new File(fileName);
	        FileInputStream is = new FileInputStream(file);
	        byteFile = new byte[(int) file.length()];
	        is.read(byteFile);
	        is.close();
	        
	        byte[] signed = signer.doSign(byteFile);
	        
	        File fw = new File(fileName+".p7s");
	        FileOutputStream os = new FileOutputStream(fw);
	        os.write(signed);
	        os.flush();
	        os.close();
	        result.setSigned(fileName+".p7s");
	        
	        
			return result;
		} catch (Throwable error) {
			error.printStackTrace();
			throw new RuntimeException(error.getMessage(), error);
		}
	}

	private void validateRequest(SignerRequest request) {
	}

	private byte[] getContent(SignerRequest request) {
		byte[] result = null;
		if (request.getFormat().equalsIgnoreCase("text")) {
			result = request.getContent().getBytes();
		} else if (request.getFormat().equalsIgnoreCase("base64")) {
			result = Base64Utils.base64Decode(request.getContent());
		} else if (request.getFormat().equalsIgnoreCase("hexa")) {
		    int len = request.getContent().length();
		    byte[] data = new byte[len / 2];
		    for (int i = 0; i < len; i += 2) {
		        data[i / 2] = (byte) ((Character.digit(request.getContent().charAt(i), 16) << 4)
		                             + Character.digit(request.getContent().charAt(i+1), 16));
		    }
		    result = data;
		}
		if (request.getCompacted()) {
		}
		return result;
	}

	public static void main(String[] args) {
		SignerRequest request = new SignerRequest();
		request.setId(1);
		request.setAlias("(1288991) JOSE RENE NERY CAILLERET CAMPANARIO");
		request.setProvider("SunPKCS11-TokenOuSmartCard_30");
		request.setContent("HELLO WORLD!");
		System.out.println(request.toJson());
		System.out.println((new Execute()).executeCommand(request));
	}

}
