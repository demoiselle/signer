package org.demoiselle.signer.core.ca.manager;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class CAManagerCache {
	private static CAManagerCache instance;
	private Map<String, Collection<X509Certificate>> cachedCertificates = new HashMap<>();
	private Map<String, Boolean> isCAofCertificate = new HashMap<>();

	private CAManagerCache() {
	}

	public static CAManagerCache getInstance() {
		if (instance == null) {
			instance = new CAManagerCache();
		}
		return instance;
	}

	Collection<X509Certificate> getCachedCertificatesFor(X509Certificate certificate) {
		return cachedCertificates.get(getCertificateIdentificator(certificate));
	}

	synchronized void addCertificate(X509Certificate certificate, Collection<X509Certificate> certificates) {
		cachedCertificates.put(getCertificateIdentificator(certificate), certificates);
	}

	Boolean getIsCAofCertificate(X509Certificate ca, X509Certificate certificate) {
		String key = getCertificateIdentificator(ca) + "|" + getCertificateIdentificator(certificate);
		return isCAofCertificate.containsKey(key) ? isCAofCertificate.get(key) : null;
	}

	synchronized void setIsCAofCertificate(X509Certificate ca, X509Certificate certificate, boolean value) {
		String key = getCertificateIdentificator(ca) + "|" + getCertificateIdentificator(certificate);
		isCAofCertificate.put(key, value);
	}

	public synchronized void invalidate() {
		cachedCertificates.clear();
		isCAofCertificate.clear();
	}

	private String getCertificateIdentificator(X509Certificate certificate) {
		return certificate.getSubjectDN().getName() + certificate.getSerialNumber().toString();
	}
}
