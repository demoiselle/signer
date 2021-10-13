/*
 * Demoiselle Framework
 * Copyright (C) 2019 SERPRO
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

package org.demoiselle.signer.policy.engine.repository;

import java.util.MissingResourceException;
import java.util.ResourceBundle;

import org.demoiselle.signer.core.util.MessagesBundle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Settings for Policies Repositories
 * Depending on the files: policy-engine-config.properties or policy-engine-config-default.properties
 *
 * @author emerson.saito@serpro.gov.br
 */
public class PolicyEngineConfig {

	private static final Logger logger = LoggerFactory.getLogger(PolicyEngineConfig.class);

	private static PolicyEngineConfig instance = null;

	// FIXME it seems a case for Properties class, not ResourceBundle.
	private static ResourceBundle bundle = null;
	private static MessagesBundle PolicyEngineMessagesBundle = new MessagesBundle();

	private String url_local_lpa_cades;
	private String url_local_lpa_cades_sha;
	private String url_local_lpa_xades;
	private String url_local_lpa_xades_sha;
	private String url_local_lpa_pades;
	private String url_local_lpa_pades_sha;

	private String url_iti_lpa_cades;
	private String url_iti_lpa_cades_sha;
	private String url_iti_lpa_xades;
	private String url_iti_lpa_xades_sha;
	private String url_iti_lpa_pades;
	private String url_iti_lpa_pades_sha;

	/**
	 * @return Returns an instance of PolicyEngineConfig
	 */
	public static PolicyEngineConfig getInstance() {
		if (instance == null) {
			instance = new PolicyEngineConfig();
		}
		return instance;
	}

	public ResourceBundle getBundle(String bundleName) {
		return ResourceBundle.getBundle(bundleName);
	}

	protected PolicyEngineConfig() {
		if (bundle == null) {
			try {
				bundle = getBundle("policy-engine-config");
			} catch (MissingResourceException mre) {
				try {
					bundle = getBundle("policy-engine-config-default");
				} catch (MissingResourceException e) {
					logger.info(e.getMessage());
				}
			}
		}
	}

	/**
	 * @return the url_local_lpa_cades
	 */
	public String getUrl_local_lpa_cades() {
		try {
			url_local_lpa_cades = bundle.getString("url_local_lpa_cades");
		} catch (MissingResourceException e) {
			throw new RuntimeException(PolicyEngineMessagesBundle.getString("error.policy.engine.config", "url_local_lpa_cades"));
		}
		return url_local_lpa_cades;
	}

	/**
	 * @param url_local_lpa_cades the url_local_lpa_cades to set
	 */
	public void setUrl_local_lpa_cades(String url_local_lpa_cades) {
		this.url_local_lpa_cades = url_local_lpa_cades;
	}

	/**
	 * @return the url_local_lpa_cades_sha
	 */
	public String getUrl_local_lpa_cades_sha() {
		try {
			url_local_lpa_cades_sha = bundle.getString("url_local_lpa_cades_sha");
		} catch (MissingResourceException e) {
			throw new RuntimeException(PolicyEngineMessagesBundle.getString("error.policy.engine.config", "url_local_lpa_cades_sha"));
		}
		return url_local_lpa_cades_sha;
	}

	/**
	 * @param url_local_lpa_cades_sha the url_local_lpa_cades_sha to set
	 */
	public void setUrl_local_lpa_cades_sha(String url_local_lpa_cades_sha) {
		this.url_local_lpa_cades_sha = url_local_lpa_cades_sha;
	}

	/**
	 * @return the url_local_lpa_xades
	 */
	public String getUrl_local_lpa_xades() {
		try {
			url_local_lpa_xades = bundle.getString("url_local_lpa_xades");
		} catch (MissingResourceException e) {
			throw new RuntimeException(PolicyEngineMessagesBundle.getString("error.policy.engine.config", "url_local_lpa_xades"));
		}
		return url_local_lpa_xades;
	}

	/**
	 * @param url_local_lpa_xades the url_local_lpa_xades to set
	 */
	public void setUrl_local_lpa_xades(String url_local_lpa_xades) {
		this.url_local_lpa_xades = url_local_lpa_xades;
	}

	/**
	 * @return the url_local_lpa_xades_sha
	 */
	public String getUrl_local_lpa_xades_sha() {
		try {
			url_local_lpa_xades_sha = bundle.getString("url_local_lpa_xades_sha");
		} catch (MissingResourceException e) {
			throw new RuntimeException(PolicyEngineMessagesBundle.getString("error.policy.engine.config", "url_local_lpa_xades_sha"));
		}
		return url_local_lpa_xades_sha;
	}

	/**
	 * @param url_local_lpa_xades_sha the url_local_lpa_xades_sha to set
	 */
	public void setUrl_local_lpa_xades_sha(String url_local_lpa_xades_sha) {
		this.url_local_lpa_xades_sha = url_local_lpa_xades_sha;
	}

	/**
	 * @return the url_local_lpa_pades
	 */
	public String getUrl_local_lpa_pades() {
		try {
			url_local_lpa_pades = bundle.getString("url_local_lpa_pades");
		} catch (MissingResourceException e) {
			throw new RuntimeException(PolicyEngineMessagesBundle.getString("error.policy.engine.config", "url_local_lpa_pades"));
		}
		return url_local_lpa_pades;
	}

	/**
	 * @param url_local_lpa_pades the url_local_lpa_pades to set
	 */
	public void setUrl_local_lpa_pades(String url_local_lpa_pades) {
		this.url_local_lpa_pades = url_local_lpa_pades;
	}

	/**
	 * @return the url_local_lpa_pades_sha
	 */
	public String getUrl_local_lpa_pades_sha() {
		try {
			url_local_lpa_pades_sha = bundle.getString("url_local_lpa_pades_sha");
		} catch (MissingResourceException e) {
			throw new RuntimeException(PolicyEngineMessagesBundle.getString("error.policy.engine.config", "url_local_lpa_pades_sha"));
		}
		return url_local_lpa_pades_sha;
	}

	/**
	 * @param url_local_lpa_pades_sha the url_local_lpa_pades_sha to set
	 */
	public void setUrl_local_lpa_pades_sha(String url_local_lpa_pades_sha) {
		this.url_local_lpa_pades_sha = url_local_lpa_pades_sha;
	}

	/**
	 * @return the url_iti_lpa_cades
	 */
	public String getUrl_iti_lpa_cades() {
		try {
			url_iti_lpa_cades = bundle.getString("url_iti_lpa_cades");
		} catch (MissingResourceException e) {
			throw new RuntimeException(PolicyEngineMessagesBundle.getString("error.policy.engine.config", "url_iti_lpa_cades"));
		}
		return url_iti_lpa_cades;
	}

	/**
	 * @param url_iti_lpa_cades the url_iti_lpa_cades to set
	 */
	public void setUrl_iti_lpa_cades(String url_iti_lpa_cades) {
		this.url_iti_lpa_cades = url_iti_lpa_cades;
	}

	/**
	 * @return the url_iti_lpa_cades_sha
	 */
	public String getUrl_iti_lpa_cades_sha() {
		try {
			url_iti_lpa_cades_sha = bundle.getString("url_iti_lpa_cades_sha");
		} catch (MissingResourceException e) {
			throw new RuntimeException(PolicyEngineMessagesBundle.getString("error.policy.engine.config", "url_iti_lpa_cades_sha"));
		}
		return url_iti_lpa_cades_sha;
	}

	/**
	 * @param url_iti_lpa_cades_sha the url_iti_lpa_cades_sha to set
	 */
	public void setUrl_iti_lpa_cades_sha(String url_iti_lpa_cades_sha) {
		this.url_iti_lpa_cades_sha = url_iti_lpa_cades_sha;
	}

	/**
	 * @return the url_iti_lpa_xades
	 */
	public String getUrl_iti_lpa_xades() {
		try {
			url_iti_lpa_xades = bundle.getString("url_iti_lpa_xades");
		} catch (MissingResourceException e) {
			throw new RuntimeException(PolicyEngineMessagesBundle.getString("error.policy.engine.config", "url_iti_lpa_xades"));
		}
		return url_iti_lpa_xades;
	}

	/**
	 * @param url_iti_lpa_xades the url_iti_lpa_xades to set
	 */
	public void setUrl_iti_lpa_xades(String url_iti_lpa_xades) {
		this.url_iti_lpa_xades = url_iti_lpa_xades;
	}

	/**
	 * @return the url_iti_lpa_xades_sha
	 */
	public String getUrl_iti_lpa_xades_sha() {
		try {
			url_iti_lpa_xades_sha = bundle.getString("url_iti_lpa_xades_sha");
		} catch (MissingResourceException e) {
			throw new RuntimeException(PolicyEngineMessagesBundle.getString("error.policy.engine.config", "url_iti_lpa_xades_sha"));
		}
		return url_iti_lpa_xades_sha;
	}

	/**
	 * @param url_iti_lpa_xades_sha the url_iti_lpa_xades_sha to set
	 */
	public void setUrl_iti_lpa_xades_sha(String url_iti_lpa_xades_sha) {
		this.url_iti_lpa_xades_sha = url_iti_lpa_xades_sha;
	}

	/**
	 * @return the url_iti_lpa_pades
	 */
	public String getUrl_iti_lpa_pades() {
		try {
			url_iti_lpa_pades = bundle.getString("url_iti_lpa_pades");
		} catch (MissingResourceException e) {
			throw new RuntimeException(PolicyEngineMessagesBundle.getString("error.policy.engine.config", "url_iti_lpa_pades"));
		}
		return url_iti_lpa_pades;
	}

	/**
	 * @param url_iti_lpa_pades the url_iti_lpa_pades to set
	 */
	public void setUrl_iti_lpa_pades(String url_iti_lpa_pades) {
		this.url_iti_lpa_pades = url_iti_lpa_pades;
	}

	/**
	 * @return the url_iti_lpa_pades_sha
	 */
	public String getUrl_iti_lpa_pades_sha() {
		try {
			url_iti_lpa_pades_sha = bundle.getString("url_iti_lpa_pades_sha");
		} catch (MissingResourceException e) {
			throw new RuntimeException(PolicyEngineMessagesBundle.getString("error.policy.engine.config", "url_iti_lpa_pades_sha"));
		}
		return url_iti_lpa_pades_sha;
	}

	/**
	 * @param url_iti_lpa_pades_sha the url_iti_lpa_pades_sha to set
	 */
	public void setUrl_iti_lpa_pades_sha(String url_iti_lpa_pades_sha) {
		this.url_iti_lpa_pades_sha = url_iti_lpa_pades_sha;
	}
}
