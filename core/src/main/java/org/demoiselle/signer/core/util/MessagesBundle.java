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

package org.demoiselle.signer.core.util;

import java.text.MessageFormat;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

/**
 * Custom Messages Bundle implementation to allows parameterization.
 *
 */
public class MessagesBundle {

	private String bundleName = "signer_core_messages";
	private static ResourceBundle resouceBundle;

	/**
	 * Default constructor using the messages.properties file
	 */
	public MessagesBundle() {
		super();
		MessagesBundle.setResouceBundle(ResourceBundle.getBundle(this.bundleName));
	}

	/**
	 *
	 * @param parmBundleName name for a .properties file
	 */
	public MessagesBundle(String parmBundleName) {
		super();
		this.bundleName = parmBundleName;
		ResourceBundle varResourceBundle = ResourceBundle.getBundle(this.bundleName);
		MessagesBundle.setResouceBundle(varResourceBundle);
	}

	/**
	 * example: getString("key.propertie.name")
	 *
	 * @param key key to be found
	 * @return value associated with key
	 */
	public String getString(String key) {
		try {
			return getResouceBundle().getString(key);
		} catch (MissingResourceException e) {
			return '!' + key + '!';
		}
	}

	/**
	 * example: getString("key.propertie.name", parm1, parm2 )
	 *
	 * @param key key to be found
	 * @param params substitution values
	 * @return value associated with key, interpolated with values
	 */
	public String getString(String key, Object... params) {
		try {
			return MessageFormat.format(getResouceBundle().getString(key), params);
		} catch (MissingResourceException e) {
			return '!' + key + '!';
		}
	}

	public static ResourceBundle getResouceBundle() {
		return resouceBundle;
	}

	public static void setResouceBundle(ResourceBundle resouceBundle) {
		MessagesBundle.resouceBundle = resouceBundle;
	}
}
