package org.demoiselle.signer.agent.desktop.command.cert;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;

import org.demoiselle.signer.agent.desktop.command.AbstractCommand;
import org.demoiselle.signer.agent.desktop.web.Execute;
import org.demoiselle.signer.signature.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.signature.core.keystore.loader.factory.KeyStoreLoaderFactory;
import com.sun.security.auth.callback.DialogCallbackHandler;

public class ListCerts extends AbstractCommand<ListCertsRequest, ListCertsResponse> {

	public ListCertsResponse doCommand(final ListCertsRequest request) {
		try {
			KeyStoreLoader loader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
			loader.setCallbackHandler(new DialogCallbackHandler());
			KeyStore keyStore = loader.getKeyStore();
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
		} catch (Throwable error) {
			throw new RuntimeException("Erro ao tentar buscar os certificados digitais");
		}
	}

	public static void main(String[] args) {
		System.out.println((new Execute()).executeCommand(new ListCertsRequest()));
	}

}
