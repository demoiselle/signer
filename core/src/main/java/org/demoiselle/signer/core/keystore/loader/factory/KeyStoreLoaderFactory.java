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

package org.demoiselle.signer.core.keystore.loader.factory;

import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoaderException;
import org.demoiselle.signer.core.keystore.loader.configuration.Configuration;
import org.demoiselle.signer.core.keystore.loader.implementation.DriverKeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.implementation.FileSystemKeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.implementation.MSKeyStoreLoader;
import org.demoiselle.signer.core.util.MessagesBundle;

import java.io.File;
import java.io.InputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * factory fo an instance of KeyStoreLoader
 *
 * @see org.demoiselle.signer.core.keystore.loader.KeyStoreLoader
 */
public class KeyStoreLoaderFactory {

	private static final Logger logger = LoggerFactory.getLogger(KeyStoreLoaderFactory.class);

	private static MessagesBundle coreMessagesBundle = new MessagesBundle();

	/**
	 * Method responsible for fabricating an instance of KeyStoreLoader based on PKCS#11.
	 * Usually this method builds chargers based on the environment settings.
	 * You can manufacture instances oriented to windows or linux environment, or else based on the JVM version. <br>
	 *
	 * @return {@link KeyStoreLoader}
	 */
	public static KeyStoreLoader factoryKeyStoreLoader() {

		logger.debug(coreMessagesBundle.getString("info.keystore.no.parameter"));
		if (Configuration.getInstance().getSO().toLowerCase().indexOf("indows") > 0) {
			logger.debug(coreMessagesBundle.getString("info.keystore.ms"));
			if (Configuration.getInstance().isMSCapiDisabled() || !Configuration.getInstance().isMSCAPI_ON()) {
				logger.debug(coreMessagesBundle.getString("info.keystore.ms.pkcs11"));
				return new DriverKeyStoreLoader();
			} else {
				logger.debug(coreMessagesBundle.getString("info.keystore.mscapi"));
				return new MSKeyStoreLoader();
			}
		} else {
			logger.debug(coreMessagesBundle.getString("info.keystore.pkcs11"));
			return new DriverKeyStoreLoader();
		}
	}

	/**
	 * Method that create an instance of AbstractKeyStoreLoader for handling of standard KeyStore PKCS#12.
	 *
	 * @param file containing keystore
	 * @return {@link KeyStoreLoader}
	 */
	public static KeyStoreLoader factoryKeyStoreLoader(File file) {
		return new FileSystemKeyStoreLoader(file);
	}


	/**
	 * Method that create an instance of AbstractKeyStoreLoader for handling of standard KeyStore PKCS#12.
	 *
	 * @param inputStream containing keystore
	 * @return {@link KeyStoreLoader}
	 */
	public static KeyStoreLoader factoryKeyStoreLoader(InputStream inputStream) {
		return new FileSystemKeyStoreLoader(inputStream);
	}

	/**
	 * Method that create an instance of AbstractKeyStoreLoader for handling of standard KeyStore PKCS#12.
	 *
	 * @param inputStream containing keystore
	 * @param type        type of keystore (maybe PKCS12 or JKS
	 * @return {@link KeyStoreLoader}
	 */
	public static KeyStoreLoader factoryKeyStoreLoader(InputStream inputStream, String type) {
		return new FileSystemKeyStoreLoader(inputStream, type);
	}

	/**
	 * Method responsible for fabricating an instance of AbstractKeyStoreLoader based on a class passed as parameter.
	 * Represents an extension point of the component, which allows the application to implement its own KeyStore loading method.
	 *
	 * @param clazz class to instantiate from
	 * @return {@link KeyStoreLoader}
	 */
	public static KeyStoreLoader factoryKeyStoreLoader(Class<? extends KeyStoreLoader> clazz) {

		if (clazz == null) {
			throw new KeyStoreLoaderException(coreMessagesBundle.getString("error.parm.clazz.null"));
		}
		KeyStoreLoader result = null;

		try {
			result = clazz.newInstance();

		} catch (IllegalAccessException | InstantiationException error) {
			throw new KeyStoreLoaderException(coreMessagesBundle.getString("error.class.instance", clazz.getCanonicalName()));
		}
		return result;
	}
}
