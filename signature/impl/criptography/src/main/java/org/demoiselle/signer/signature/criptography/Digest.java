/*
 * Demoiselle Framework
 * Copyright (C) 2010 SERPimport java.io.File;

import br.gov.frameworkdemoiselle.criptography.implementation.DigestImpl;
ile is part of Demoiselle Framework.
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

import java.io.File;

import org.demoiselle.signer.signature.criptography.implementation.DigestImpl;

/**
 * Define o comportamento padrão para utilização de algoritmos de resumo.
 * 
 * @see {@link DigestImpl}
 */
public interface Digest {

	/**
	 * Seta o algoritmo utilizado pelo método de resumo.
	 * 
	 * @see {@link DigestAlgorithmEnum}
	 */
	public void setAlgorithm(DigestAlgorithmEnum algorithm);

	/**
	 * Seta o algoritmo utilizado pelo método de resumo.
	 * 
	 * @see {@link DigestAlgorithmEnum}
	 */
	public void setAlgorithm(String algorithm);

	/**
	 * Método responsável por gerar um resumo do conteudo passado como
	 * parametro, utilizando para isso o algoritmo setado pelo método
	 * setAlgorithm()
	 */
	public byte[] digest(byte[] content);

	/**
	 * Retorna o resumo de um array de bytes no formato de caracteres
	 * hexadecimais.
	 * 
	 * @param content
	 *            Array de bytes
	 * @return caracteres hexadecimais
	 */
	public String digestHex(byte[] content);

	/**
	 * Retorna o resumo de um arquivo
	 * 
	 * @param file
	 *            Arquivo
	 * @return array de bytes
	 */
	public byte[] digestFile(File file);

	/**
	 * Retorna o resumo de um arquivo no formato de caracteres hexadecimais
	 * 
	 * @param file
	 *            arquivo
	 * @return caracteres hexadecimais
	 */
	public String digestFileHex(File file);

}
