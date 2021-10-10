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

package org.demoiselle.signer.cryptography;

import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;

import javax.crypto.SecretKey;

/**
 * Defines the default behavior for using encryption.
 * Can be symmetric or asymmetric, it depends only on its implementation.
 *
 * @see org.demoiselle.signer.cryptography.implementation.CriyptographyImpl
 */
public interface Cryptography {

	/**
	 * Changes the algorithm and symmetric encryption settings to be used.
	 *
	 * @param algorithm algorithm representation
	 * @see SymmetricAlgorithmEnum
	 */
	void setAlgorithm(SymmetricAlgorithmEnum algorithm);

	/**
	 * Changes the algorithm and settings for asymmetric cryptography to be used.
	 *
	 * @param algorithm algorithm representation
	 * @see AsymmetricAlgorithmEnum
	 */
	void setAlgorithm(AsymmetricAlgorithmEnum algorithm);

	/**
	 * Changes only the encryption algorithm to be used.
	 *
	 * @param algorithm algorithm name
	 */
	void setAlgorithm(String algorithm);

	/**
	 * Alters only the key of the algorithm to be used
	 *
	 * @param keyAlgorithm algorithm name
	 */
	void setKeyAlgorithm(String keyAlgorithm);

	/**
	 * Changes the encryption provider to be used.
	 *
	 * @param provider new provider
	 * @see com.sun.crypto.provider.SunJCE
	 */
	@SuppressWarnings("restriction")
	void setProvider(Provider provider);

	/**
	 * Change the size of the key if it is necessary to generate the key.
	 *
	 * @param size key size
	 */
	void setSize(int size);

	/**
	 * A cryptographic key is required to perform encryption.
	 * Symmetric Encryption uses {@link SecretKey}
	 * Asymmetric encryption uses {@link PublicKey} and {@link PrivateKey}
	 *
	 * @param key key
	 */
	void setKey(Key key);

	/**
	 * Returns the content passed as parameter, encrypted.
	 *
	 * @param content content to be ciphered
	 * @return ciphered content
	 */
	byte[] cipher(byte[] content);

	/**
	 * Returns the content passed as a parameter, decrypted.
	 *
	 * @param content ciphered content to be decrypted
	 * @return decrypted content
	 */
	byte[] decipher(byte[] content);

	/**
	 * Generates key for encryption.
	 *
	 * @return generated key
	 */
	Key generateKey();
}
