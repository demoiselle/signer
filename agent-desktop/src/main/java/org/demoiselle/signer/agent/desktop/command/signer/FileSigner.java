package org.demoiselle.signer.agent.desktop.command.signer;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;

import org.demoiselle.signer.agent.desktop.command.AbstractCommand;
import org.demoiselle.signer.agent.desktop.ui.PinHandler;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.factory.KeyStoreLoaderFactory;
import org.demoiselle.signer.core.util.Base64Utils;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory.Policies;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS7Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;

public class FileSigner extends AbstractCommand<SignerRequest, SignerResponse> {

	// TODO Arquivo de controle de MENU
	// TODO Opção atachado e desatachado
	@Override
	public SignerResponse doCommand(final SignerRequest request) {

		try {

			SignerResponse result = new SignerResponse();
			String resultFileName = sign(request.getAlias(), request.getSignaturePolicy(),
					new String(this.getContent(request)));
			result.setSigned(resultFileName);

			return result;
		} catch (Throwable error) {
			error.printStackTrace();
			throw new RuntimeException(error.getMessage(), error);
		}
	}

	public byte[] makeSignature(String alias, String signaturePolicy, String fileName) {
		KeyStoreLoader loader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
		loader.setCallbackHandler(new PinHandler());
		KeyStore keyStore = loader.getKeyStore();
		try {
			PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
			PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
			signer.setCertificates(keyStore.getCertificateChain(alias));
			signer.setPrivateKey(privateKey);
			signer.setAlgorithm(SignerAlgorithmEnum.SHA512withRSA);
			Policies policie = null;
			try {
				policie = Policies.valueOf(signaturePolicy);
			} catch (Throwable error) {
				policie = Policies.AD_RB_CADES_2_2;
			}
			signer.setSignaturePolicy(policie);

			byte[] byteFile = null;

			File file = new File(fileName);
			FileInputStream is = new FileInputStream(file);
			byteFile = new byte[(int) file.length()];
			is.read(byteFile);
			is.close();

			// return signer.doAttachedSign(byteFile);
			return signer.doDetachedSign(byteFile);

		} catch (Throwable error) {
			error.printStackTrace();
			throw new RuntimeException(error.getMessage(), error);
		}

	}

	public String sign(String alias, String signaturePolicy, String fileName) throws IOException {

		File fw = new File(fileName + ".p7s");
		FileOutputStream os = new FileOutputStream(fw);
		os.write(makeSignature(alias, signaturePolicy, fileName));
		os.flush();
		os.close();

		return fileName + ".p7s";

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
						+ Character.digit(request.getContent().charAt(i + 1), 16));
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
