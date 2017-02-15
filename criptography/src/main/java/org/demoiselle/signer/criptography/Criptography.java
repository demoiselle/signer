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

package org.demoiselle.signer.criptography;

import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;

import javax.crypto.SecretKey;

import org.demoiselle.signer.criptography.implementation.CriptographyImpl;

import com.sun.crypto.provider.SunJCE;

/**
 * Define o comportamento padrão para utilização de criptografia. Seja simétrico
 * ou assimétrico, depende apenas de sua implementação.
 * 
 * @see {@link CriptographyImpl}
 */
public interface Criptography {

	/**
	 * Altera o algoritmo e configurações de criptografia a ser utilizado.
	 * 
	 * @see {@link SymmetricAlgorithmEnum}, {@link AsymmetricAlgorithmEnum}
	 */
	public void setAlgorithm(SymmetricAlgorithmEnum algorithm);

	/**
	 * Altera o algoritmo e configurações de criptografia a ser utilizado.
	 * 
	 * @param algorithm
	 * @see {@link SymmetricAlgorithmEnum}, {@link AsymmetricAlgorithmEnum}
	 */
	public void setAlgorithm(AsymmetricAlgorithmEnum algorithm);

	/**
	 * Altera apenas o algoritmo de criptografia a ser utilizado.
	 * 
	 * @param algorithm
	 */
	public void setAlgorithm(String algorithm);

	/**
	 * Altera apenas a chave do algoritmo a ser utilizado
	 * 
	 * @param keyAlgorithm
	 */
	public void setKeyAlgorithm(String keyAlgorithm);

	/**
	 * Altera o provider de criptografia a ser utilizado.
	 * 
	 * @see {@link SunJCE}
	 */
	public void setProvider(Provider provider);

	/**
	 * Altera o tamanho da chave, caso seja necessário gerar a chave.
	 */
	public void setSize(int size);

	/**
	 * É necessário uma chave criptográfica para a realização da criptografia
	 * Criptografia simétrica utiliza {@link SecretKey} Criptografia assimétrica
	 * utiliza {@link PublicKey} e {@link PrivateKey}
	 */
	public void setKey(Key key);

	/**
	 * Retorna o conteudo passado como parametro criptografado.
	 */
	public byte[] cipher(byte[] content);

	/**
	 * Retorna o conteudo passado como parametro descriptografado.
	 */
	public byte[] decipher(byte[] content);

	/**
	 * Gera chave para criptografia.
	 */
	public Key generateKey();
}