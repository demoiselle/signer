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

package org.demoiselle.signer.chain.icp.brasil.provider;

import java.util.MissingResourceException;
import java.util.ResourceBundle;

import org.demoiselle.signer.core.util.MessagesBundle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provide locations for ICP-Brasil Chain and corresponding hash values.
 * It depends on the files "chain-icpbrasil-config.properties" or
 * "chain-icpbrasil-config-default.properties".
 *
 * @author emerson.saito@serpro.gov.br
 */
public class ChainICPBrasilConfig {

	private static final Logger logger = LoggerFactory.getLogger(ChainICPBrasilConfig.class);

	private static ChainICPBrasilConfig instance = null;

	// FIXME it seems a case for Properties (https://www.baeldung.com/java-properties)
	private static ResourceBundle bundle = null;
	private static final MessagesBundle ChainICPBrasilMessagesBundle = new MessagesBundle();

	private String url_local_ac_list;
	private String url_local_ac_list_sha512;
	private String url_iti_ac_list;
	private String url_iti_ac_list_sha512;

	// FIXME system file specific
	private String local_dir = "/tmp";

	/**
	 * @return Returns an instance of ChainICPBrasilConfig
	 */
	public static ChainICPBrasilConfig getInstance() {
		if (instance == null) {
			instance = new ChainICPBrasilConfig();
		}
		return instance;
	}

	public ResourceBundle getBundle(String bundleName) {
		return ResourceBundle.getBundle(bundleName);
	}

	protected ChainICPBrasilConfig() {
		if (bundle == null) {
			try {
				bundle = getBundle("chain-icpbrasil-config");
			} catch (MissingResourceException mre) {
				try {
					bundle = getBundle("chain-icpbrasil-config-default");
				} catch (MissingResourceException e) {
					logger.info(e.getMessage());
				}
			}
		}
	}

	/**
	 * @return the url_local_ac_list
	 */
	public String getUrl_local_ac_list() {
		try {
			setUrl_local_ac_list(bundle.getString("url_local_ac_list"));
		} catch (MissingResourceException e) {
			logger.error(ChainICPBrasilMessagesBundle.getString("error.chain.ipcbrasil.config", "url_local_ac_list")+"\n"+e.getMessage());
			throw new RuntimeException(ChainICPBrasilMessagesBundle.getString("error.chain.ipcbrasil.config", "url_local_ac_list"));
		}
		return url_local_ac_list;
	}

	/**
	 * @param url_local_ac_list the url_local_ac_list to set
	 */
	public void setUrl_local_ac_list(String url_local_ac_list) {
		this.url_local_ac_list = url_local_ac_list;
	}

	/**
	 * @return the url_local_ac_list_sha512
	 */
	public String getUrl_local_ac_list_sha512() {
		try {
			setUrl_local_ac_list_sha512(bundle.getString("url_local_ac_list_sha512"));
		} catch (MissingResourceException e) {
			logger.error(ChainICPBrasilMessagesBundle.getString("error.chain.ipcbrasil.config", "url_local_ac_list_sha512")+"\n"+e.getMessage());
			throw new RuntimeException(ChainICPBrasilMessagesBundle.getString("error.chain.ipcbrasil.config", "url_local_ac_list_sha512"));
		}
		return url_local_ac_list_sha512;
	}

	/**
	 * @param url_local_ac_list_sha512 the url_local_ac_list_sha512 to set
	 */
	public void setUrl_local_ac_list_sha512(String url_local_ac_list_sha512) {
		this.url_local_ac_list_sha512 = url_local_ac_list_sha512;
	}

	/**
	 * @return the url_iti_ac_list
	 */
	public String getUrl_iti_ac_list() {
		try {
			setUrl_iti_ac_list(bundle.getString("url_iti_ac_list"));
		} catch (MissingResourceException e) {
			logger.error(ChainICPBrasilMessagesBundle.getString("error.chain.ipcbrasil.config", "url_iti_ac_list")+"\n"+e.getMessage());
			throw new RuntimeException(ChainICPBrasilMessagesBundle.getString("error.chain.ipcbrasil.config", "url_iti_ac_list"));
		}
		return url_iti_ac_list;
	}

	/**
	 * @param url_iti_ac_list the url_iti_ac_list to set
	 */
	public void setUrl_iti_ac_list(String url_iti_ac_list) {
		this.url_iti_ac_list = url_iti_ac_list;
	}

	/**
	 * @return the url_iti_ac_list_sha512
	 */
	public String getUrl_iti_ac_list_sha512() {
		try {
			setUrl_iti_ac_list_sha512(bundle.getString("url_iti_ac_list_sha512"));
		} catch (MissingResourceException e) {
			logger.error(ChainICPBrasilMessagesBundle.getString("error.chain.ipcbrasil.config", "url_iti_ac_list_sha512")+"\n"+e.getMessage());
			throw new RuntimeException(ChainICPBrasilMessagesBundle.getString("error.chain.ipcbrasil.config", "url_iti_ac_list_sha512"));
		}
		return url_iti_ac_list_sha512;
	}

	/**
	 * @param url_iti_ac_list_sha512 the url_iti_ac_list_sha512 to set.
	 */
	public void setUrl_iti_ac_list_sha512(String url_iti_ac_list_sha512) {
		this.url_iti_ac_list_sha512 = url_iti_ac_list_sha512;
	}

	/**
	 * @return the local_dir.
	 */
	public String getLocal_dir() {
		try {
			setLocal_dir(bundle.getString("local_dir"));
		} catch (MissingResourceException e) {
			logger.info(ChainICPBrasilMessagesBundle.getString("error.chain.ipcbrasil.config", "local_dir")+"\n"+e.getMessage());
			// FIXME system file specific
			local_dir = "/tmp";
		}
		return local_dir;
	}

	/**
	 * @param local_dir the local_dir to set.
	 */
	public void setLocal_dir(String local_dir) {
		this.local_dir = local_dir;
	}
}
