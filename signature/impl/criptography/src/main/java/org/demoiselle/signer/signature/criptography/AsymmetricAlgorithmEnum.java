/*
 * Demoiselle Framework
 * Copyright (C) 2010 SERPRO
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

package org.demoiselle.signer.signature.criptography;

/**
 * Define os algoritmos usados para criptografia assimétrica padrão ICP-Brasil<br/>
 * Para mais informações, ler documento PADRÕES E ALGORITMOS CRIPTOGRÁFICOS DA
 * ICP-BRASIL (<i>DOC ICP-01.01</i>)<br/>
 * <br/>
 * <b>Geração de Chaves Assimétricas de AC</b><br>
 * Normativo ICP-Brasil = DOC-ICP-01 - item 6.1.1.3, DOC-ICP-04 - item 6.1.1.3,
 * DOC-ICP-01 - item 6.1.5, DOC-ICP-05 - item 6.1.5<br/>
 * Algoritmo = RSA, ECDSA (conforme RFC 5480)<br/>
 * Tamanho de chave = RSA 2048, RSA 4096, ECDSA 512<br/>
 * <br/>
 * <b>Geração de Chaves Assimétricas de Usuário Final</b><br/>
 * Normativo ICP-Brasil = DOC-ICP-04 - item 6.1.5.2<br/>
 * Algoritmo = RSA, ECDSA (conforme RFC 5480)<br/>
 * Tamanho da chave A1, A2, A3, S1, S2, S3, T3 = RSA 1024, RSA 2048, ECDSA 256<br/>
 * Tamanho da chave A4, S4, T4 = RSA 2048, RSA 4096, ECDSA 512<br/>
 * 
 */
public enum AsymmetricAlgorithmEnum {

	/**
	 * <a href="http://www.rsa.com/rsalabs/node.asp?id=2125">http://www.rsa.com/
	 * rsalabs/node.asp?id=2125</a>
	 */
	RSA("RSA/ECB/PKCS1Padding"),
	// RSA 1024, RSA 2048, RSA 4096

	/**
	 * <a href="http://www.faqs.org/rfcs/rfc4050.html">http://www.faqs.org/rfcs/
	 * rfc4050.html</a>
	 */
	ECDSA("ECDSA");
	// ECDSA 256, ECDSA 512

	/**
	 * Definicao de algoritmo padrao.
	 */
	public static AsymmetricAlgorithmEnum DEFAULT = AsymmetricAlgorithmEnum.RSA;

	/**
	 * Definicao de algoritmo padrao.
	 */
	private String algorithm;

	private AsymmetricAlgorithmEnum(String algorithm) {
		this.algorithm = algorithm;
	}

	public String getAlgorithm() {
		return this.algorithm;
	}

	/**
	 * Recupera um item do enum correspondente ao parâmetro passado. O parâmetro
	 * passado deverá ser igual (case insensitive) ao nome do algoritmo de algum
	 * item deste enum, caso contrário retornará null.
	 */
	public static AsymmetricAlgorithmEnum getAsymmetricAlgorithmEnum(String algorithm) {
		for (AsymmetricAlgorithmEnum value : AsymmetricAlgorithmEnum.values()) {
			if (value.getAlgorithm().equalsIgnoreCase(algorithm)) {
				return value;
			}
		}
		return null;
	}

}
