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
import org.demoiselle.signer.signature.cades.SignerAlgorithmEnum;
import org.demoiselle.signer.signature.cades.factory.PKCS7Factory;
import org.demoiselle.signer.signature.cades.pkcs7.PKCS7Signer;
import org.demoiselle.signer.signature.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.signature.core.keystore.loader.factory.KeyStoreLoaderFactory;
import org.demoiselle.signer.signature.core.util.Base64Utils;
import org.demoiselle.signer.signature.policy.engine.factory.PolicyFactory.Policies;

public class FileSigner extends AbstractCommand<SignerRequest, SignerResponse>{

	@Override
	public SignerResponse doCommand(final SignerRequest request) {
		
		
		try {
			
	        SignerResponse result = new SignerResponse();
			String resultFileName = sign(request.getAlias(), request.getSignaturePolicy(), new String(this.getContent(request)));
	        result.setSigned(resultFileName);
	        
			return result;
		} catch (Throwable error) {
			error.printStackTrace();
			throw new RuntimeException(error.getMessage(), error);
		}
	}

	public String sign(String alias, String signaturePolicy, String fileName){
		KeyStoreLoader loader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
		loader.setCallbackHandler(new PinHandler());
		KeyStore keyStore = loader.getKeyStore();
		try {
			X509Certificate cert = (X509Certificate)keyStore.getCertificate(alias);
	        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);        
			PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
	        signer.setCertificates(keyStore.getCertificateChain(alias));
	        signer.setPrivateKey(privateKey);
	        signer.setAlgorithm(SignerAlgorithmEnum.SHA512withRSA);
	        Policies policie = null;
	        try {
	        	policie = Policies.valueOf(signaturePolicy);
	        } catch (Throwable error) {
	        	policie = Policies.AD_RB_CADES_2_1;
	        }
	        signer.setSignaturePolicy(policie);
	        signer.setAttached(false);
	        
	        byte[] byteFile = null;
	        SignerResponse result = new SignerResponse();
	        
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
	        
			return fileName+".p7s";
		} catch (Throwable error) {
			error.printStackTrace();
			throw new RuntimeException(error.getMessage(), error);
		}
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
	}

}
