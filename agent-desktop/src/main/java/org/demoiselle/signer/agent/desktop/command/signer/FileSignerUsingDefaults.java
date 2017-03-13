package org.demoiselle.signer.agent.desktop.command.signer;

import java.io.File;
import java.io.IOException;

import javax.swing.JFileChooser;

import org.demoiselle.signer.agent.desktop.command.AbstractCommand;
import org.demoiselle.signer.agent.desktop.command.cert.ListCerts;
import org.demoiselle.signer.agent.desktop.command.cert.ListCertsRequest;
import org.demoiselle.signer.agent.desktop.command.cert.ListCertsResponse;
import org.demoiselle.signer.agent.desktop.command.policy.ListPolicies;
import org.demoiselle.signer.agent.desktop.command.policy.ListPoliciesRequest;
import org.demoiselle.signer.agent.desktop.command.policy.ListPoliciesResponse;
import org.demoiselle.signer.agent.desktop.ui.JFileChooserPolicy;
import org.demoiselle.signer.agent.desktop.ui.ListCertificateData;

public class FileSignerUsingDefaults extends AbstractCommand<SignerRequest, SignerResponse> {

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
		if (lr.getCertificates().size() > 1) {
			ListCertificateData lcd = new ListCertificateData(lr);
			lcd.init();
			alias = lcd.getAlias();
		} else
			alias = lr.getCertificates().iterator().next().getAlias();

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
