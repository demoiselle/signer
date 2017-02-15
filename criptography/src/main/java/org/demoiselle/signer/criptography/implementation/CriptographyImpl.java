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

package org.demoiselle.signer.criptography.implementation;

import java.security.Key;
import java.security.Provider;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.demoiselle.signer.criptography.AsymmetricAlgorithmEnum;
import org.demoiselle.signer.criptography.Criptography;
import org.demoiselle.signer.criptography.CriptographyException;
import org.demoiselle.signer.criptography.SymmetricAlgorithmEnum;

import com.sun.crypto.provider.SunJCE;

/**
 * Implementação padrão da interface {@link Criptography}
 */
public class CriptographyImpl implements Criptography {

	private String algorithm;
	private String keyAlgorithm;
	private Integer size;
	private Provider provider = new SunJCE();
	private Key key;
	private Cipher cipher;

	public CriptographyImpl() {
		setAlgorithm(SymmetricAlgorithmEnum.DEFAULT);
	}

	@Override
	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}

	@Override
	public void setAlgorithm(SymmetricAlgorithmEnum algorithm) {
		this.algorithm = algorithm.getAlgorithm();
		this.keyAlgorithm = algorithm.getKeyAlgorithm();
		this.size = algorithm.getSize();
	}

	@Override
	public void setAlgorithm(AsymmetricAlgorithmEnum algorithm) {
		this.algorithm = algorithm.getAlgorithm();
	}

	@Override
	public void setProvider(Provider provider) {
		this.provider = provider;
		if (provider != null) {
			Security.addProvider(this.provider);
		}
	}

	@Override
	public void setSize(int size) {
		this.size = size;
	}

	@Override
	public void setKeyAlgorithm(String keyAlgorithm) {
		this.keyAlgorithm = keyAlgorithm;
	}

	@Override
	public void setKey(Key key) {
		this.key = key;
	}

	/**
	 * Método que gera uma chave criptográfica utilizando o algoritmo setado
	 * pelo método setAlgorithm() Caso tenha sido informado algum provider, este
	 * também será utilizado para a geração da chave. A chave gerada é para
	 * apenas criptografia simétrica, então a chave gerada por este método é
	 * obrigatoriamente uma chave do tipo {@link SecretKey}
	 * 
	 * @return
	 */
	public Key generateKey() {
		try {
			KeyGenerator genKey;
			if (this.provider == null) {
				genKey = KeyGenerator.getInstance(this.keyAlgorithm);
			} else {
				genKey = KeyGenerator.getInstance(this.keyAlgorithm, this.provider);
			}
			if (this.size != null) {
				genKey.init(this.size);
			}
			return genKey.generateKey();
		} catch (Exception e) {
			throw new CriptographyException("Error: Could not generate key", e);
		}
	}

	/**
	 * Método que criptografa um conteudo informado como byte[] Utiliza o
	 * algoritmo setado pelo método setAlgorithm() Caso tenha sido informado
	 * algum provider, este também será utilizado.
	 */
	@Override
	public byte[] cipher(byte[] content) {
		try {
			return crypt(content, Cipher.ENCRYPT_MODE);
		} catch (Throwable e) {
			throw new CriptographyException("Encrypt Error", e);
		}
	}

	/**
	 * Método que descriptografa um conteudo informado como byte[] Utiliza o
	 * algoritmo setado pelo método setAlgorithm() Caso tenha sido informado
	 * algum provider, este também será utilizado.
	 */
	@Override
	public byte[] decipher(byte[] content) {
		try {
			return crypt(content, Cipher.DECRYPT_MODE);
		} catch (Throwable e) {
			throw new CriptographyException("Decrypt Error", e);
		}
	}

	/**
	 * Executa o algoritmo de criptografia no modo de cifragem ou decifragem É
	 * necessário setar a chave criptografica antes de encriptar um conteudo
	 * 
	 * @param content
	 *            conteúdo original
	 * @param crypt_mode
	 *            modo cifragem ou decifrafem
	 * @return conteúdo processado
	 */
	private byte[] crypt(byte[] content, int crypt_mode) {
		try {
			if (provider == null) {
				this.cipher = Cipher.getInstance(this.algorithm);
			} else {
				this.cipher = Cipher.getInstance(this.algorithm, this.provider);
			}
			if (this.key == null) {
				throw new CriptographyException("Key is null");
			}
			this.cipher.init(crypt_mode, this.key);
			return this.cipher.doFinal(content);
		} catch (Throwable e) {
			throw new CriptographyException("Crypt Error", e);
		}
	}

}
