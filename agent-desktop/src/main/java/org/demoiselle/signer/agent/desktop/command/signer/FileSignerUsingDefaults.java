package org.demoiselle.signer.agent.desktop.command.signer;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

import javax.swing.JFileChooser;

import org.demoiselle.signer.agent.desktop.command.AbstractCommand;
import org.demoiselle.signer.agent.desktop.command.cert.Certificate;
import org.demoiselle.signer.agent.desktop.command.cert.ListCerts;
import org.demoiselle.signer.agent.desktop.command.cert.ListCertsRequest;
import org.demoiselle.signer.agent.desktop.command.cert.ListCertsResponse;
import org.demoiselle.signer.agent.desktop.command.policy.ListPolicies;
import org.demoiselle.signer.agent.desktop.command.policy.ListPoliciesRequest;
import org.demoiselle.signer.agent.desktop.command.policy.ListPoliciesResponse;
import org.demoiselle.signer.agent.desktop.ui.JFileChooserPolicy;
import org.demoiselle.signer.agent.desktop.ui.ListCertificateData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FileSignerUsingDefaults extends AbstractCommand<SignerRequest, SignerResponse> {

	private static final Logger logger = LoggerFactory.getLogger(FileSignerUsingDefaults.class);

	@Override
	public SignerResponse doCommand(final SignerRequest request) {

		try {
			return sign();
		} catch (Throwable error) {
			throw new RuntimeException(error.getMessage(), error);
		}
	}

	public SignerResponse sign() throws IOException {

		SignerResponse result = new SignerResponse();

		String fileName = "";
		String alias;
		String signatureFileName = "";

		ListCertsRequest requestCert = new ListCertsRequest();
		requestCert.setUseForSignature(true);

		ListCerts ls = new ListCerts();
		ListCertsResponse lr = ls.doCommand(requestCert);

		logger.info("Token");
		logger.info("Tamanho: " + lr.getCertificates().size());
		logger.info("Vazio: " + lr.getCertificates().isEmpty());

		// Quando não existe token na máquina
		if (lr.getCertificates().isEmpty()) {
			throw new RuntimeException(
					"Nenhum certificado foi encontrado, verifique se seu token esta conectar ao computador, caso esteja feche e abra novamente o assinador.");
		}

		if (lr.getCertificates().size() > 1) {
			ListCertificateData lcd = new ListCertificateData(lr);
			lcd.init();
			alias = lcd.getAlias();
		} else {
			ArrayList<Certificate> list = (ArrayList<Certificate>) lr.getCertificates();
			Certificate cert = list.iterator().next();
			alias = cert.getAlias();
		}

		ListPoliciesResponse rp = (new ListPolicies()).doCommand(new ListPoliciesRequest());
		JFileChooserPolicy fileChooser = new JFileChooserPolicy(rp.getPolicies());

		int returnValue = fileChooser.showOpenDialog(null);
		if (returnValue == JFileChooser.APPROVE_OPTION) {
			File selectedFile = fileChooser.getSelectedFile();
			fileName = selectedFile.getAbsolutePath();
			FileSigner fs = new FileSigner();
			signatureFileName = fs.sign(alias, fileChooser.getPolicy(), fileName);
		} else if (returnValue == JFileChooser.CANCEL_OPTION) {
			result.setActionCanceled(true);
		}

		result.setSigned(signatureFileName);
		result.setOriginal(fileName);

		return result;
	}

}
