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

package org.demoiselle.signer.core.keystore.loader.implementation;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;

import javax.security.auth.callback.CallbackHandler;

import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoaderException;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementing KeyStore loading based on PKCS12 or JKS standards
 */
public class FileSystemKeyStoreLoader implements KeyStoreLoader {

	private static final String FILE_TYPE_PKCS12 = "PKCS12";
	private static final String FILE_TYPE_JKS = "JKS";
	private static MessagesBundle coreMessagesBundle = new MessagesBundle();
	private static final Logger logger = LoggerFactory.getLogger(FileSystemKeyStoreLoader.class);
	private File fileKeyStore = null;
	private InputStream inputStreamKeyStore = null;
	private String type = FILE_TYPE_PKCS12;

	/**
	 * Class constructor that checks whether the specified parameter exists and whether it is a file.
	 *
	 * @param file File representing a KeyStore of type PKCS12 or JKS
	 */
	public FileSystemKeyStoreLoader(File file) {

		if (file == null || !file.exists() || !file.isFile()) {
			throw new KeyStoreLoaderException(coreMessagesBundle.getString("error.file.invalid"));
		}

		this.setFileKeyStore(file);

	}

	/**
	 * Class constructor that checks whether the specified
	 * parameters exist and whether they are valid.
	 *
	 * @param inputStream the input.
	 * @param type the type.
	 */
	public FileSystemKeyStoreLoader(InputStream inputStream, String type) {

		if (inputStream == null) {
			throw new KeyStoreLoaderException(coreMessagesBundle.getString("error.input.stream.invalid"));
		}
		if (type == null || type.isEmpty()) {
			throw new KeyStoreLoaderException(coreMessagesBundle.getString("error.keystore.type.invalid"));
		}
		if (!type.equalsIgnoreCase("PKCS12") && !type.equalsIgnoreCase("JKS")) {
			throw new KeyStoreLoaderException(coreMessagesBundle.getString("error.keystore.type.invalid"));
		}
		this.setInputStreamKeyStore(inputStream);
		this.setType(type);
	}

	/**
	 * Class constructor for default type PKCS12, that checks
	 * whether the specified parameter exists.
	 *
	 * @param inputStream the input.
	 */
	public FileSystemKeyStoreLoader(InputStream inputStream) {

		if (inputStream == null) {
			throw new KeyStoreLoaderException(coreMessagesBundle.getString("error.input.stream.invalid"));
		}

		this.setInputStreamKeyStore(inputStream);
		this.setType(FILE_TYPE_PKCS12);
	}

	/**
	 * @return PCKS12 or JKS keystore file.
	 */
	public File getFileKeyStore() {
		return fileKeyStore;
	}

	public void setFileKeyStore(File fileKeyStore) {
		this.fileKeyStore = fileKeyStore;
	}


	public InputStream getInputStreamKeyStore() {
		return inputStreamKeyStore;
	}

	public void setInputStreamKeyStore(InputStream inputStreamKeyStore) {
		this.inputStreamKeyStore = inputStreamKeyStore;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	/**
	 * Attempts to load the KeyStore first in the PKCS12 pattern.
	 * If this is not possible, it will store the received exception and
	 * then attempt to load a KeyStore into the JKS standard.
	 * Failing in both attempts, it will throw an exception.
	 *
	 * @param pinNumber pin
	 * @return keystore
	 */
	public KeyStore getKeyStore(String pinNumber) {

		logger.info("FileSystemKeyStoreLoader.getKeyStore()");

		KeyStore result = null;
		if (this.fileKeyStore != null) {
			//String extensao = fileKeyStore.getName().substring(fileKeyStore.getName().lastIndexOf("."), fileKeyStore.getName().length());
			if (fileKeyStore.getName().endsWith("p12") || fileKeyStore.getName().endsWith("pfx")) {
				try {
					result = this.getKeyStoreWithType(pinNumber, FILE_TYPE_PKCS12);
				} catch (Throwable throwable) {
					throw new KeyStoreLoaderException(coreMessagesBundle.getString("error.keyStore.pass", fileKeyStore.getName()), throwable);
				}
			} else {
				if (fileKeyStore.getName().endsWith("jks")) {
					try {
						result = this.getKeyStoreWithType(pinNumber, FILE_TYPE_JKS);
					} catch (Throwable error) {
						throw new KeyStoreLoaderException(coreMessagesBundle.getString("error.keyStore.pass", fileKeyStore.getName()), error);
					}
				} else {
					throw new KeyStoreLoaderException(coreMessagesBundle.getString("error.keyStore.unknow.format", fileKeyStore.getName()));
				}
			}

		} else {
			try {
				result = this.getKeyStoreWithTypeFromInputStream(pinNumber);

			} catch (Throwable throwable) {
				throw new KeyStoreLoaderException(coreMessagesBundle.getString("error.keyStore.pass"), throwable);
			}

		}
		return result;
	}

	/**
	 * Not implemented, use getKeyStore (pinNumer)
	 *
	 * @return NULL
	 */
	@Override
	public KeyStore getKeyStore() {
		logger.error("Nao implementado");
		return null;
	}

	/**
	 * @param pinNumber    pin
	 * @param keyStoreType PKSC12 or JKS
	 * @return keystore
	 */
	private KeyStore getKeyStoreWithType(String pinNumber, String keyStoreType) {
		KeyStore result = null;
		try {
			result = KeyStore.getInstance(keyStoreType);
			char[] pwd = pinNumber == null ? null : pinNumber.toCharArray();
			InputStream is = new FileInputStream(this.fileKeyStore);
			result.load(is, pwd);
		} catch (Throwable error) {
			throw new KeyStoreLoaderException(coreMessagesBundle.getString("error.keystore.from.file"), error);
		}
		return result;
	}

	/**
	 * @param pinNumber pin
	 * @return keystore
	 */
	private KeyStore getKeyStoreWithTypeFromInputStream(String pinNumber) {
		KeyStore result = null;
		try {
			result = KeyStore.getInstance(this.type);
			char[] pwd = pinNumber == null ? null : pinNumber.toCharArray();
			result.load(this.inputStreamKeyStore, pwd);
		} catch (Throwable error) {
			throw new KeyStoreLoaderException(coreMessagesBundle.getString("error.keystore.from.inputstream"), error);
		}
		return result;
	}

	@Override
	public void setCallbackHandler(CallbackHandler callback) {
		// TODO Auto-generated method stub
	}
}
