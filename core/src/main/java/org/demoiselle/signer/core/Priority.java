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

package org.demoiselle.signer.core;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 * Used to prioritize some execution flow, as methods annotated
 * with @startup or @shutdown.
 */
@Target({TYPE, METHOD})
@Retention(RUNTIME)
public @interface Priority {

	/**
	 * Most important priority value.
	 */
	int MAX_PRIORITY = Integer.MIN_VALUE;

	/**
	 * Less important priority value.
	 */
	int MIN_PRIORITY = Integer.MAX_VALUE;

	/**
	 * Less important priority value.
	 */
	int L1_PRIORITY = MIN_PRIORITY;

	/**
	 * Higher priority than L1_PRIORITY
	 */
	int L2_PRIORITY = L1_PRIORITY - 100;

	/**
	 * Higher priority than L2_PRIORITY
	 */
	int L3_PRIORITY = L2_PRIORITY - 100;

	/**
	 * Higher priority than L3_PRIORITY
	 */
	int L4_PRIORITY = L3_PRIORITY - 100;

	/**
	 * An integer value defines the priority order.
	 * The lower the value, the greater the priority.
	 *
	 * @return The priority value.
	 */
	int value();
}
