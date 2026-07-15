/*
 * Demoiselle Framework
 * Copyright (C) 2016 SERPRO
 * ----------------------------------------------------------------------------
 * This file is part of Demoiselle Framework.
 *
 * Demoiselle Framework is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License version 3
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License version 3
 * along with this program; if not,  see <http://www.gnu.org/licenses/>
 * or write to the Free Software Foundation, Inc., 51 Franklin Street,
 * Fifth Floor, Boston, MA  02110-1301, USA.
 * ----------------------------------------------------------------------------
 * Este arquivo é parte do Framework Demoiselle.
 *
 * O Framework Demoiselle é um software livre; você pode redistribuí-lo e/ou
 * modificá-lo dentro dos termos da GNU LGPL versão 3 como publicada pela Fundação
 * do Software Livre (FSF).
 *
 * Este programa é distribuído na esperança que possa ser útil, mas SEM NENHUMA
 * GARANTIA; sem uma garantia implícita de ADEQUAÇÃO a qualquer MERCADO ou
 * APLICAÇÃO EM PARTICULAR. Veja a Licença Pública Geral GNU/LGPL em português
 * para maiores detalhes.
 *
 * Você deve ter recebido uma cópia da GNU LGPL versão 3, sob o título
 * "LICENCA.txt", junto com esse programa. Se não, acesse <http://www.gnu.org/licenses/>
 * ou escreva para a Fundação do Software Livre (FSF) Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA 02111-1301, USA.
 */

package org.demoiselle.signer.core.ca.manager;

import java.util.ArrayList;
import java.util.List;

import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.LinkedList;
import javax.security.auth.x500.X500Principal;

import org.demoiselle.signer.core.ca.provider.ProviderCA;
import org.demoiselle.signer.core.ca.provider.ProviderCAFactory;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Validate and Load trusted Certificate Authority chain
 */
public class CAManager {

	private static final String CN = "CN";
	private static final CAManager instance = new CAManager();
	private static final Logger LOGGER = LoggerFactory.getLogger(CAManager.class);
	private static MessagesBundle coreMessagesBundle = new MessagesBundle();

	private CAManager() {
	}

	public static CAManager getInstance() {
		return CAManager.instance;
	}

	public boolean validateRootCAs(Collection<X509Certificate> cas, X509Certificate certificate) {
		boolean valid = false;

		for (X509Certificate ca : cas) {
			try {
				this.validateRootCA(ca, certificate);
				valid = true;
				break;
			} catch (CAManagerException error) {
				LOGGER.debug(error.getMessage());
			}
		}

		if (!valid) {
			LOGGER.error(coreMessagesBundle.getString("error.no.authority"));
			throw new CAManagerException(coreMessagesBundle.getString("error.no.authority"));
		}

		return true;
	}

	public boolean validateRootCA(X509Certificate ca, X509Certificate certificate) {
		if (ca == null) {
			LOGGER.error(coreMessagesBundle.getString("error.root.ca.not.informed"));
			throw new CAManagerException(coreMessagesBundle.getString("error.root.ca.not.informed"));
		}

		if (!this.isRootCA(ca)) {
			LOGGER.error(coreMessagesBundle.getString("error.not.root"));
			throw new CAManagerException(coreMessagesBundle.getString("error.not.root"));
		}

		Collection<X509Certificate> acs = this.getCertificateChain(certificate);

		if (acs == null || acs.isEmpty()) {
			LOGGER.error(coreMessagesBundle.getString("error.get.chain"));
			throw new CAManagerException(coreMessagesBundle.getString("error.get.chain"));
		}

		X509Certificate rootCA = null;
		for (X509Certificate x509 : acs) {
			if (this.isRootCA(x509)) {
				rootCA = x509;
				break;
			}
		}

		if (rootCA == null) {
			LOGGER.error(coreMessagesBundle.getString("error.root.ca.not.found"));
			throw new CAManagerException(coreMessagesBundle.getString("error.root.ca.not.found"));
		}

		if (!this.isCAofCertificate(rootCA, ca)) {
			LOGGER.error(coreMessagesBundle.getString("error.root.ca.not.chain"));
			throw new CAManagerException(coreMessagesBundle.getString("error.root.ca.not.chain"));
		}

		return true;
	}

	public boolean isRootCA(X509Certificate ca) {
		if (ca == null) {
			return false;
		}
		// Validação estrita da auto-assinatura (Padrão para Produção)
		if (this.isCAofCertificate(ca, ca)) {
			return true;
		}
		
		// Fallback por identidade apenas se explicitamente configurado para ambiente de homologação/teste
		String env = System.getProperty("org.demoiselle.signer.env");
		if ("hom".equalsIgnoreCase(env) || "homolog".equalsIgnoreCase(env)) {
			if (ca.getSubjectX500Principal().equals(ca.getIssuerX500Principal())) {
				LOGGER.debug("AC Raiz de Homologação identificada por identidade (assinatura não validada).");
				return true;
			}
		}
		return false;
	}

	public boolean isCAofCertificate(X509Certificate ca, X509Certificate certificate) {
		CAManagerCache managerCache = CAManagerCache.getInstance();
		boolean isCached = CAManagerConfiguration.getInstance().isCached();

		//TODO - verificar se precisa lançar exceção ou não ser método de retorno boolean
		try {
			LOGGER.debug(coreMessagesBundle.getString("info.ca.cache", isCached));
			if (isCached) {
				Boolean isValid = managerCache.getIsCAofCertificate(ca, certificate);
				if (null != isValid) {
					return isValid;
				}
			}
			certificate.verify(ca.getPublicKey());
			LOGGER.debug(coreMessagesBundle.getString("info.ca.validated"));

			if (isCached) {
				managerCache.setIsCAofCertificate(ca, certificate, true);
			}

			return true;
		} catch (SignatureException | InvalidKeyException error) {
			LOGGER.debug(coreMessagesBundle.getString("error.ca.verify.certificate.signature", error.getMessage()));
			if (isCached) {
				managerCache.setIsCAofCertificate(ca, certificate, false);
			}
			return false;
		} catch (CertificateException error) {
			LOGGER.error(coreMessagesBundle.getString("error.certificate.exception"), error);
			throw new CAManagerException(coreMessagesBundle.getString("error.certificate.exception"), error);
		} catch (NoSuchAlgorithmException error) {
			LOGGER.error(coreMessagesBundle.getString("error.no.such.algorithm"), error);
			throw new CAManagerException(coreMessagesBundle.getString("error.no.such.algorithm"), error);
		} catch (NoSuchProviderException error) {
			LOGGER.error(coreMessagesBundle.getString("error.no.such.provider"), error);
			throw new CAManagerException(coreMessagesBundle.getString("error.no.such.provider"), error);
		}
	}

	public Certificate[] getCertificateChainArray(X509Certificate certificate) {
		Certificate[] result;

		LinkedList<X509Certificate> chain = (LinkedList<X509Certificate>) this.getCertificateChain(certificate);

		if (chain == null || chain.isEmpty()) {
			return new Certificate[]{};
		}

		result = new Certificate[chain.size()];

		for (int i = 0; i < chain.size(); i++) {
			result[i] = chain.get(i);
		}

		return result;
	}

	/**
	 * Get ALL certificate chains previously added in
	 *
	 * @param certificate final certificate in the desired chain
	 * @return list of certificates
	 */
	public synchronized Collection<X509Certificate> getCertificateChain(X509Certificate certificate) {
		CAManagerConfiguration config = CAManagerConfiguration.getInstance();
		
		// Tentando obter cadeia de certificados do cache
		if (config.isCached()) {
			LOGGER.debug(coreMessagesBundle.getString("info.cache.mode", config.isCached()));
			CAManagerCache managerCache = CAManagerCache.getInstance();
			Collection<X509Certificate> certificates = managerCache.getCachedCertificatesFor(certificate);
			if (certificates != null) {
				return certificates;
			}
		}

		LinkedList<X509Certificate> result = new LinkedList<>();
		result.add(certificate);
		if (this.isRootCA(certificate)) {
			return result;
		}

		// Coleta TODAS as CAs de TODOS os providers primeiro
		// Isso resolve o problema de cadeias espalhadas entre providers (ex: Intermediária no Provedor A e Raiz no B)
		List<X509Certificate> allCAs = new ArrayList<>();
		Collection<ProviderCA> providers = ProviderCAFactory.getInstance().factory();
		for (ProviderCA provider : providers) {
			try {
				allCAs.addAll(provider.getCAs());
			} catch (Exception e) {
				LOGGER.warn(coreMessagesBundle.getString("error.no.ca", provider.getName()));
			}
		}

		boolean ok = false;
		X509Certificate current = certificate;
		
		// Tenta construir a cadeia navegando pelos emissores
		while (current != null && !this.isRootCA(current)) {
			X509Certificate issuer = null;
			X500Principal issuerPrincipal = current.getIssuerX500Principal();
			String issuerCN = this.getCN(issuerPrincipal.getName());
			
			for (X509Certificate ca : allCAs) {
				// Tenta comparação exata de Principals primeiro (mais seguro)
				boolean match = issuerPrincipal.equals(ca.getSubjectX500Principal());
				
				// Fallback para comparação de CN (legado/robusto para variações de encoding)
				if (!match) {
					String caCN = this.getCN(ca.getSubjectX500Principal().getName());
					match = issuerCN.equalsIgnoreCase(caCN);
				}
				
				if (match && this.isCAofCertificate(ca, current)) {
					issuer = ca;
					break;
				}
			}
			
			if (issuer != null) {
				// Evita loops infinitos caso haja circularidade (improvável mas seguro)
				if (result.contains(issuer)) {
					break; 
				}
				result.add(issuer);
				current = issuer;
				if (this.isRootCA(current)) {
					ok = true;
				}
			} else {
				// Não encontrou emisor para o certificado atual
				current = null;
			}
		}

		if (!ok) {
			LOGGER.error("Fornecedor (Issuer) do certificado: {}", certificate.getIssuerX500Principal());
			LOGGER.error("Cadeia parcial construída ({} elemento(s)):", result.size());
			int chainIdx = 0;
			for (X509Certificate chainCert : result) {
				if (chainCert != null) {
					LOGGER.error("  [{}] Subject: {} | Issuer: {}", chainIdx++, chainCert.getSubjectX500Principal(), chainCert.getIssuerX500Principal());
				}
			}
			LOGGER.error(coreMessagesBundle.getString("erro.no.chain.provided", certificate.getSubjectDN()));
			throw new CAManagerException(coreMessagesBundle.getString("erro.no.chain.provided", certificate.getSubjectDN()));
		}

		if (config.isCached() && !result.isEmpty()) {
			CAManagerCache.getInstance().addCertificate(certificate, result);
		}

		return result;
	}

	@SuppressWarnings("unused")
	private X509Certificate getCAFromCertificate(Collection<X509Certificate> certificates,
												 X509Certificate certificate) {
		if (this.isRootCA(certificate) || certificates == null || certificates.isEmpty()) {
			return null;
		}

		for (X509Certificate ca : certificates) {
			if (this.isCAofCertificate(ca, certificate)) {
				return ca;
			}
		}

		return null;
	}

	public Certificate[] getCertificateChainArray(KeyStore keyStore, String privateKeyPass, String certificateAlias) {
		Certificate[] certificateChain;

		try {
			keyStore.getKey(certificateAlias, privateKeyPass.toCharArray());
			certificateChain = keyStore.getCertificateChain(certificateAlias);

			if (certificateChain == null) {
				LOGGER.error(coreMessagesBundle.getString("error.no.chain.alias", certificateAlias));
				throw new CAManagerException(coreMessagesBundle.getString("error.no.chain.alias", certificateAlias));
			}
		} catch (KeyStoreException error) {
			LOGGER.error(coreMessagesBundle.getString("error.keystore.type"), error);
			throw new CAManagerException(coreMessagesBundle.getString("error.keystore.type"), error);
		} catch (UnrecoverableKeyException error) {
			LOGGER.error(coreMessagesBundle.getString("error.unrecoverable.key"), error);
			throw new CAManagerException(coreMessagesBundle.getString("error.unrecoverable.key"), error);
		} catch (NoSuchAlgorithmException error) {
			LOGGER.error(coreMessagesBundle.getString("error.no.such.algorithm"), error);
			throw new CAManagerException(coreMessagesBundle.getString("error.no.such.algorithm"), error);
		}

		return certificateChain;
	}

	public Collection<X509Certificate> getCertificateChain(KeyStore keyStore, String privateKeyPass,
														   String certificateAlias) {
		Collection<X509Certificate> result;

		Certificate[] certificateChain = this.getCertificateChainArray(keyStore, privateKeyPass, certificateAlias);

		if (certificateChain != null) {
			result = new LinkedList<>();
			for (Certificate certificate : certificateChain) {
				result.add((X509Certificate) certificate);
			}
		} else {
			LOGGER.error(coreMessagesBundle.getString("error.no.chain.alias"));
			throw new CAManagerException(coreMessagesBundle.getString("error.no.chain.alias"));
		}

		return result;
	}

	private String getCN(String x500) {
		if (x500 == null) return "";
		String upper = x500.toUpperCase();
		int indexCN = upper.indexOf("CN=");
		if (indexCN >= 0) {
			int indexComa = x500.indexOf(',', indexCN);
			if (indexComa < 0) {
				return x500.substring(indexCN).trim();
			}
			return x500.substring(indexCN, indexComa).trim();
		}
		return x500;
	}
}
