package org.demoiselle.signer.agent.desktop.command.cert;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;

import org.demoiselle.signer.agent.desktop.command.AbstractCommand;
import org.demoiselle.signer.agent.desktop.exception.ActionCanceled;
import org.demoiselle.signer.agent.desktop.ui.PinHandler;
import org.demoiselle.signer.agent.desktop.web.Execute;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoaderException;
import org.demoiselle.signer.core.keystore.loader.factory.KeyStoreLoaderFactory;

public class ListCerts extends AbstractCommand<ListCertsRequest, ListCertsResponse> {

	@SuppressWarnings("deprecation")
	public ListCertsResponse doCommand(final ListCertsRequest request) {
		try {

			String action = (request.isUseForSignature() ? "Assinar um Documento" : "Listar os certificados");

			PinHandler pin = new PinHandler(action);
			KeyStoreLoader loader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
			loader.setCallbackHandler(pin);
			KeyStore keyStore = null;

			try {
				keyStore = loader.getKeyStore();
			} catch (KeyStoreLoaderException e) {
				// Ignore error because maybe the user dont fill pass
				// e.printStackTrace();
			}

			if (pin.getPwd().equals("") && pin.getActionCanceled()) {
				throw new ActionCanceled();
			} else if (keyStore == null || pin.getPwd().equals("")) {
				throw new RuntimeException(
						"Ocorreu um erro ao acessar o token, verifique se esta conectado ao computador.");
			}

			Enumeration<String> aliases = keyStore.aliases();
			ListCertsResponse response = new ListCertsResponse();
			response.setCertificates(new ArrayList<Certificate>());
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
				Certificate certJson = new Certificate();
				certJson.setAlias(alias);
				certJson.setProvider(keyStore.getProvider().getName());
				certJson.setSubject(cert.getSubjectDN().getName());
				certJson.setNotAfter(cert.getNotAfter().toGMTString());
				certJson.setNotBefore(cert.getNotBefore().toGMTString());
				response.getCertificates().add(certJson);
			}
			return response;
		} catch (ActionCanceled e) {
			throw new RuntimeException("Ação cancelada pelo usuário");
		} catch (Throwable error) {
			if (!error.getMessage().equals(null)) {
				throw new RuntimeException("Erro ao tentar buscar os certificados digitais. " + error.getMessage());
			} else {
				throw new RuntimeException("Erro ao tentar buscar os certificados digitais. Erro desconhecido.");
			}
		}
	}

	public static void main(String[] args) {
		System.out.println((new Execute()).executeCommand(new ListCertsRequest()));
	}

}
