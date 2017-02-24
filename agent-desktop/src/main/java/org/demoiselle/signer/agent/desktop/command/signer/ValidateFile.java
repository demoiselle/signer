package org.demoiselle.signer.agent.desktop.command.signer;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import javax.swing.JFileChooser;
import javax.swing.filechooser.FileFilter;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.Store;
import org.demoiselle.signer.agent.desktop.command.AbstractCommand;
import org.demoiselle.signer.agent.desktop.command.cert.Certificate;
import org.demoiselle.signer.agent.desktop.web.Execute;
import org.demoiselle.signer.core.ca.manager.CAManager;
import org.demoiselle.signer.policy.impl.cades.SignerException;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS7Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;

public class ValidateFile extends AbstractCommand<ValidateFileRequest, ValidateResponse> {

	@Override
	public ValidateResponse doCommand(final ValidateFileRequest request) {
		ValidateResponse response = new ValidateResponse();

		File contentFilePath = null;
		File signedFilePath = null;
		
		String contentFile = request.getContent();
		JFileChooser fileChooser = new JFileChooser();
		if (contentFile == null || contentFile.isEmpty()) {
			fileChooser.setDialogTitle("Selecione o Arquivo de Conteúdo");
			int returnValue = fileChooser.showOpenDialog(null);
			if (returnValue == JFileChooser.APPROVE_OPTION)
				contentFilePath = fileChooser.getSelectedFile();
		} else {
			contentFilePath = new File(contentFile);
		}
		
		if (contentFilePath == null) {
			response.setMessage("Favor escolher o arquivo de conteúdo.");
			return response;
		}
		
		String signedFile = request.getSignature();
		if (signedFile == null || signedFile.isEmpty()) {
			fileChooser.setDialogTitle("Selecione o Arquivo de Assinatura");
			fileChooser.setFileFilter(new FileFilter() {
				public String getDescription() {
					return "Arquivo da Assinatura (.p7s)";
				}
				public boolean accept(File f) {
					return f.getName().endsWith(".p7s");
				}
			});
			int returnValue = fileChooser.showOpenDialog(null);
			if (returnValue == JFileChooser.APPROVE_OPTION)
				signedFilePath = fileChooser.getSelectedFile();
		} else {
			signedFilePath = new File(signedFile);
		}
		if (signedFilePath == null) {
			response.setMessage("Favor escolher o arquivo de assinatura.");
			return response;
		}
		
		byte[] content = new byte[(int)contentFilePath.length()];
		byte[] signed = new byte[(int)signedFilePath.length()];
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(contentFilePath);
			fis.read(content);
			fis.close();
		} catch (Throwable error) {
			this.processException(error, response);
			return response;
		}
		
		try {
			fis = new FileInputStream(signedFilePath);
			fis.read(signed);
			fis.close();
		} catch (Throwable error) {
			this.processException(error, response);
			return response;
		}

		PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
		try {
			response.setValid(signer.check(content, signed));
			if (response.isValid())
				response.setMessage("Assinatura digital válida em conformidade ao padrão ICP-Brasil (DOC-ICP-15)");
		} catch (Throwable error) {
			this.processException(error, response);
		}

		Certificate by = new Certificate();
		try {
			List<X509Certificate> chain = this.getCertData(content, signed);
			X509Certificate x509by = chain.get(0);
			by.setSubject(x509by.getSubjectDN().getName());
			by.setNotAfter(x509by.getNotAfter().toGMTString());
			by.setNotBefore(x509by.getNotBefore().toGMTString());
		} catch (Throwable error) {
			throw new RuntimeException("Erro ao tentar interpretar o conteudo da assinatura.", error);
		}
		
		response.setBy(by);
		
		return response;
	}
	
	private void processException(Throwable error, ValidateResponse response) {
		error.printStackTrace();
		response.setValid(false);
		response.setMessage(error.getMessage());
		if (error.getCause() != null && error.getCause().getMessage() != null)
			response.setCausedBy(error.getCause().getMessage());
	}
	
	public <T> LinkedList<X509Certificate> getCertData(byte[] content, byte[] signed) throws CertificateException, IOException {
		CMSSignedData cmsSignedData = null;
		try {
			if (content == null) {
				cmsSignedData = new CMSSignedData(signed);
			} else {
				cmsSignedData = new CMSSignedData(new CMSProcessableByteArray(content), signed);
			}
		} catch (CMSException ex) {
			throw new SignerException("Bytes inválidos localizados no pacote PKCS7.", ex);
		}
		@SuppressWarnings("unchecked")
		Store<T> certStore = cmsSignedData.getCertificates();
		SignerInformationStore signers = cmsSignedData.getSignerInfos();
		Iterator<?> it = signers.getSigners().iterator();
		while (it.hasNext()) {
			SignerInformation signer = (SignerInformation) it.next();
			@SuppressWarnings("unchecked")
			Collection<T> certCollection = certStore.getMatches(signer.getSID());
			Iterator<?> certIt = certCollection.iterator();
			X509CertificateHolder certificateHolder = (X509CertificateHolder) certIt.next();
			X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certificateHolder);
			LinkedList<X509Certificate> cas = (LinkedList<X509Certificate>)CAManager.getInstance().getCertificateChain(cert);
			return cas;
		}
		return null;
	}

	public static void main(String[] args) throws Throwable {
		ValidateRequest request = new ValidateFileRequest();
//		request.setContent("/home/09275643784/acesso.serpro.HOD.LOC");
		request.setSignature("/home/09275643784/acesso.serpro.HOD.LOC.p7s");
		System.out.println((new Execute()).executeCommand(request));
	}
	
}
