package org.demoiselle.signer.agent.desktop.command.signer;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.demoiselle.signer.agent.desktop.command.AbstractCommand;
import org.demoiselle.signer.agent.desktop.command.cert.Certificate;
import org.demoiselle.signer.agent.desktop.ui.PinHandler;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.factory.KeyStoreLoaderFactory;
import org.demoiselle.signer.core.util.Base64Utils;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory.Policies;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS7Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;

public class Signer extends AbstractCommand<SignerRequest, SignerResponse> {

	@SuppressWarnings("deprecation")
	@Override
	public SignerResponse doCommand(final SignerRequest request) {

		this.validateRequest(request);

		KeyStoreLoader loader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
		loader.setCallbackHandler(new PinHandler("Assinar um texto"));
		KeyStore keyStore = loader.getKeyStore();
		try {
			X509Certificate cert = (X509Certificate) keyStore.getCertificate(request.getAlias());
			PrivateKey privateKey = (PrivateKey) keyStore.getKey(request.getAlias(), null);
			PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
			signer.setCertificates(keyStore.getCertificateChain(request.getAlias()));
			signer.setPrivateKey(privateKey);
			Policies policie = null;
			try {
				policie = Policies.valueOf(request.getSignaturePolicy());
			} catch (Throwable error) {
				error.printStackTrace();
				policie = Policies.AD_RB_CADES_2_2;
			}
			signer.setSignaturePolicy(policie);
			byte[] signed = signer.doDetachedSign(
					this.contentToBytes(request.getContent(), request.getFormat(), request.getCompacted()));
			String encripted = Base64Utils.base64Encode(signed);
			SignerResponse result = new SignerResponse();
			result.setRequestId(request.getRequestId());
			result.setSigned(encripted);
			Certificate by = new Certificate();
			by.setAlias(request.getAlias());
			by.setProvider(keyStore.getProvider().getName());
			by.setSubject(cert.getSubjectDN().getName());
			by.setNotAfter(cert.getNotAfter().toGMTString());
			by.setNotBefore(cert.getNotBefore().toGMTString());
			result.setBy(by);
			result.setPublicKey(Base64Utils.base64Encode(cert.getPublicKey().getEncoded()));
			return result;
		} catch (Throwable error) {
			error.printStackTrace();
			throw new RuntimeException(error.getMessage(), error);
		}
	}

	private void validateRequest(SignerRequest request) {
	}

}