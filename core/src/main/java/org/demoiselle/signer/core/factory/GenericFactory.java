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
 *
 */

package org.demoiselle.signer.core.factory;

import org.demoiselle.signer.core.exception.SignerException;
import org.demoiselle.signer.core.util.MessagesBundle;

/**
 * Abstract factory that concentrates the reading of the configurations for
 * all the other specialized factories as well as the class reflection functionalities.
 */
abstract public class GenericFactory<F> {

	private String className = null;
	private static final MessagesBundle coreMessagesBundle = new MessagesBundle();

	/**
	 * Main method of the factory.
	 * This method makes classes from the names of classes defined in environment variables.
	 * Such variables are defined by each concrete factory that implements the abstract factory through the getVariableName () method.
	 * Once the environment variable is read, the value of the variable is stored in the "className" property.
	 * If the environment variable is not set, a default object is built through the abstract factoryDefault () method.
	 *
	 * @return Instance of factory
	 */
	public F factory() {
		if (this.className == null) {
			this.className = this.getContentFromVariables(getVariableName());
		}

		F result = null;
		if (this.className != null && this.className.length() > 0) {
			result = this.factoryFromClassName(this.className);
		} else {
			result = this.factoryDefault();
		}

		return result;
	}

	/**
	 * Instantiate an object from the name of your class
	 *
	 * @param className class name of new instance
	 * @return new instance
	 */
	@SuppressWarnings("all")
	public F factoryFromClassName(String className) {
		F result = null;

		Class clazz = null;
		try {
			clazz = Class.forName(className);
		} catch (Throwable error) {
			throw new SignerException(coreMessagesBundle.getString("error.class.not.exist", className), error);
		}
		if (clazz != null) {
			try {
				result = (F) clazz.newInstance();
			} catch (Throwable error) {
				throw new SignerException(coreMessagesBundle.getString("error.class.incompatible", clazz.getCanonicalName()), error);
			}
		}

		return result;
	}

	/**
	 * Search the environment variables or JVM variables for a certain value.
	 * The priority is for the environment variables.
	 *
	 * @param key Variable location key
	 * @return the content defined in one of the variables. NULL, if no variable is defined
	 */
	private String getContentFromVariables(String key) {
		String content = System.getenv(key);
		if (content == null) {
			content = System.getenv(key.toLowerCase());
		}
		if (content == null) {
			content = System.getenv(key.toUpperCase());
		}

		if (content == null) {
			content = System.getProperty(key);
		}
		if (content == null) {
			content = System.getProperty(key.toLowerCase());
		}
		if (content == null) {
			content = System.getProperty(key.toUpperCase());
		}

		return content;
	}

	/**
	 * It forces the concrete class to fabricate an object by default
	 *
	 * @return new instance
	 */
	public abstract F factoryDefault();

	/**
	 * Every concrete factory needs to define which environment variable
	 * contains the name of the class to be fabricated
	 *
	 * @return variable name
	 */
	protected abstract String getVariableName();

}
