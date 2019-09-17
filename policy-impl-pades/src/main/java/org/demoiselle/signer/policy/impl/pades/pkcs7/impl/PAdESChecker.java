package org.demoiselle.signer.policy.impl.pades.pkcs7.impl;

import java.util.List;

import org.demoiselle.signer.policy.impl.cades.SignatureInformations;
import org.demoiselle.signer.policy.impl.cades.pkcs7.impl.CAdESChecker;
import org.demoiselle.signer.policy.impl.pades.pkcs7.PKCS7Checker;

public class PAdESChecker implements PKCS7Checker {

	private CAdESChecker cAdESChecker = new CAdESChecker();
	
	@Override
	public List<SignatureInformations> checkAttachedSignature(byte[] signedData) {

		return cAdESChecker.checkAttachedSignature(signedData);
	}

	@Override	
	public List<SignatureInformations> checkDetattachedSignature(
			byte[] content, byte[] signedData) {
		return cAdESChecker.checkDetachedSignature(content, signedData);
	}

	@Override
	public List<SignatureInformations> checkDetachedSignature(byte[] content,
			byte[] signedData) {
		return cAdESChecker.checkDetachedSignature(content, signedData);
	}

	@Override
	public List<SignatureInformations> checkSignatureByHash(
			String digestAlgorithmOID, byte[] calculatedHashContent,
			byte[] signedData) {
		// TODO Auto-generated method stub
		return cAdESChecker.checkSignatureByHash(digestAlgorithmOID, calculatedHashContent, signedData);
	}

	@Override
	public List<SignatureInformations> getSignaturesInfo() {
		// TODO Auto-generated method stub
		return cAdESChecker.getSignaturesInfo();
	}

}
