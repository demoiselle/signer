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
import org.demoiselle.signer.core.util.Base64Utils;
import org.demoiselle.signer.policy.impl.cades.SignerException;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS7Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;

public class Validate extends AbstractCommand<ValidateRequest, ValidateResponse> {

	@SuppressWarnings("deprecation")
	@Override
	public ValidateResponse doCommand(final ValidateRequest request) {
		ValidateResponse response = new ValidateResponse();
		byte[] content = this.contentToBytes(request.getContent(), request.getFormat());
		byte[] signed = this.contentToBytes(request.getSignature(), request.getFormat());
		PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
		try {
			response.setValid(signer.check(content, signed));
			if (response.isValid())
				response.setMessage("Assinatura digital válida em conformidade ao padrão ICP-Brasil (DOC-ICP-15)");
		} catch (Throwable error) {
			response.setValid(false);
			response.setMessage(error.getMessage());
			if (error.getCause() != null && error.getCause().getMessage() != null)
				response.setCausedBy(error.getCause().getMessage());
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
		File fileContent = new File("/home/09275643784/acesso.serpro.HOD.LOC");
		File fileSigned = new File("/home/09275643784/acesso.serpro.HOD.LOC.p7s");
		fileSigned = new File("/home/09275643784/acesso.serpro.HOD.p7s");
		fileSigned = new File("/home/09275643784/bbd.p7s");
		FileInputStream fis = new FileInputStream(fileContent);
		byte[] content = new byte[(int)fileContent.length()];
		fis.read(content);
		fis.close();
		fis = new FileInputStream(fileSigned);
		byte[] signed = new byte[(int)fileSigned.length()];
		fis.read(signed);
		fis.close();
		String contentBase64 = Base64Utils.base64Encode(content);
		String signedBase64 = Base64Utils.base64Encode(signed);
		ValidateRequest request = new ValidateRequest();
		request.setContent("marco");
		request.setSignature(signedBase64);
		request.setFormat("base64");
		System.out.println(request.toJson());
		System.out.println((new Execute()).executeCommand(request));
	}

}
