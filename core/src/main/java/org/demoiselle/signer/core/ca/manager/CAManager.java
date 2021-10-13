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

		return this.isCAofCertificate(ca, ca);
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
	public Collection<X509Certificate> getCertificateChain(X509Certificate certificate) {
		CAManagerConfiguration config = CAManagerConfiguration.getInstance();
		Collection<X509Certificate> result = new LinkedList<>();

		// Tentando obter cadeia de certificados do cache
		if (config.isCached()) {
			LOGGER.debug(coreMessagesBundle.getString("info.cache.mode", config.isCached()));
			CAManagerCache managerCache = CAManagerCache.getInstance();
			Collection<X509Certificate> certificates = managerCache.getCachedCertificatesFor(certificate);
			// Se encontrar no cache
			if (certificates != null) {
				return certificates;
			}
		}

		result.add(certificate);
		if (this.isRootCA(certificate)) {
			return result;
		}

		Collection<ProviderCA> providers = ProviderCAFactory.getInstance().factory();

		boolean ok = false;
		for (ProviderCA provider : providers) {
			try {
				String varNameProvider = provider.getName();
				LOGGER.debug(coreMessagesBundle.getString("info.searching.on.provider", varNameProvider));

				// Get ALL CAs of ONE provider
				Collection<X509Certificate> acs = provider.getCAs();

				// Variable to control if go to next Provider is necessery
				// Iterate this provider to create a Cert Chain
				for (X509Certificate ac : acs) {
					// If is CA issuer of certificate
					X500Principal issuer = certificate.getIssuerX500Principal();
					if (issuer != null) {
						String issuerName = certificate.getIssuerX500Principal().getName();
						String certificateCnIssuer = this.getCN(issuerName);
						String acCN = this.getCN(ac.getSubjectX500Principal().getName());
						if (certificateCnIssuer.equalsIgnoreCase(acCN) && this.isCAofCertificate(ac, certificate)) {
							result.add(ac);
							X509Certificate acFromAc = null;

							for (X509Certificate ac2 : acs) {
								// If is CA Issuer of CA issuer
								String acCnIssuer = this.getCN(ac.getIssuerX500Principal().getName());
								String ac2CN = this.getCN(ac2.getSubjectX500Principal().getName());
								if (acCnIssuer.equalsIgnoreCase(ac2CN) && this.isCAofCertificate(ac2, ac)) {
									acFromAc = ac2;
								}
							}

							while (acFromAc != null) {
								// If the chain was created SET OK
								result.add(acFromAc);

								// If Certificate is ROOT end while
								if (this.isRootCA(acFromAc)) {
									ok = true;
									break;
								} else {
									for (X509Certificate ac3 : acs) {
										// If is CA Issuer of CA issuer
										String acFromAcIssuerCN = this.getCN(acFromAc.getIssuerX500Principal().getName());
										String ac3CN = this.getCN(ac3.getSubjectX500Principal().getName());
										if (acFromAcIssuerCN.equalsIgnoreCase(ac3CN) && this.isCAofCertificate(ac3, acFromAc)) {
											acFromAc = ac3;
										}
									}
								}
							}
						}
						if (ok) {
							break;
						}
					}

				}

				LOGGER.debug(coreMessagesBundle.getString("info.found.levels", result.size(), provider.getName()));

				// If chain is created BREAK! Doesn't go to next Provider
				if (ok) {
					break;
				} else {
					LOGGER.info(coreMessagesBundle.getString("warn.no.chain.on.provider", provider.getName()));
				}
			} catch (Exception error) {
				LOGGER.warn(coreMessagesBundle.getString("error.no.ca", provider.getName()));
			}
		}

		if (!ok) {
			LOGGER.error(coreMessagesBundle.getString("erro.no.chain.provided", certificate.getSubjectDN()));
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
		int indexCN = x500.indexOf(CN);
		if (indexCN >= 0) {
			int indexComa = x500.indexOf(',', indexCN);
			if (indexComa < 0) {
				return x500.substring(indexCN);
			}
			return x500.substring(indexCN, indexComa);
		}
		return x500;
	}
}
