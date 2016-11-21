/*
 * Demoiselle Framework
 * Copyright (C) 2010 SERPRO
 * --import br.gov.frameworkdemoiselle.criptography.Digest;
import br.gov.frameworkdemoiselle.criptography.implementation.DigestImpl;
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

package org.demoiselle.signer.signature.criptography.factory;

import org.demoiselle.signer.signature.criptography.Digest;
import org.demoiselle.signer.signature.criptography.implementation.DigestImpl;

/**
 * Fábrica especializada em fabricar objetos da interface {@link Digest}
 */
public class DigestFactory extends GenericFactory<Digest> {

	public static final DigestFactory instance = new DigestFactory();

	public static final DigestFactory getInstance() {
		return DigestFactory.instance;
	}

	/**
	 * Define um objeto padrão para a fábrica O Componente possue uma
	 * implementação default
	 * 
	 * @see {@link DigestImpl}
	 */
	@Override
	public Digest factoryDefault() {
		return new DigestImpl();
	}

	/**
	 * Define a variável de ambiente utilizada pela fábrica abstrata a fim de
	 * buscar o nome da classe a ser fabricada.
	 */
	@Override
	protected String getVariableName() {
		return "digest.implementation";
	}

}
