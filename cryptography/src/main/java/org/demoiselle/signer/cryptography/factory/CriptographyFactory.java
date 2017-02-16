/*
 * Demoiselle Framework
 * Copyright (C) 2016 SERPRO
 * --import br.gov.frameworkdemoiselle.criptography.Criptography;
import br.gov.frameworkdemoiselle.criptography.implementation.CriptographyImpl;
selle Framework is free software; you can redistribute it and/or
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

package org.demoiselle.signer.cryptography.factory;

import org.demoiselle.signer.cryptography.Criptography;
import org.demoiselle.signer.cryptography.implementation.CriptographyImpl;

/**
 * Fábrica especializada em fabricar objetos da interface {@link Criptography}
 */
public class CriptographyFactory extends GenericFactory<Criptography> {

	public static final CriptographyFactory instance = new CriptographyFactory();

	public static final CriptographyFactory getInstance() {
		return CriptographyFactory.instance;
	}

	/**
	 * Define um objeto padrão para a fábrica O Componente possue uma
	 * implementação default
	 * 
	 * @see {@link CriptographyImpl}
	 */
	@Override
	public Criptography factoryDefault() {
		return new CriptographyImpl();
	}

	/**
	 * Define a variável de ambiente utilizada pela fábrica abstrata a fim de
	 * buscar o nome da classe a ser fabricada.
	 */
	@Override
	protected String getVariableName() {
		return "criptography.implementation";
	}

}