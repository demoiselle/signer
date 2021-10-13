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

package org.demoiselle.signer.core.ca.manager;

public class CAManagerConfiguration {

	/**
	 * System key to set cached or not cached
	 */
	public static final String CACHED = "signer.camanager.cached";
	public static final String ENV_CACHED = "SIGNER_CAMANAGER_CACHED";

	public static CAManagerConfiguration instance = new CAManagerConfiguration();
	private boolean isCached;

	/**
	 * Check for system variables. If there is, assign in class variables otherwise use default values.
	 */
	private CAManagerConfiguration() {
		String cachedProp = System.getenv(ENV_CACHED);
		if (cachedProp == null || cachedProp.isEmpty()) {
			cachedProp = (String) System.getProperties().get(CACHED);
			if (cachedProp == null || cachedProp.isEmpty()) {
				setCached(true);
			} else {
				setCached(Boolean.valueOf(cachedProp));
			}
		} else {
			setCached(Boolean.valueOf(cachedProp));
		}
	}

	/**
	 * to static single instance
	 *
	 * @return current instance
	 */
	public static CAManagerConfiguration getInstance() {
		return instance;
	}

	/**
	 * Returns whether the CAManager is cached (TRUE) or not (FALSE)
	 *
	 * @return true (cached) or false (not cached)
	 */
	public boolean isCached() {
		return isCached;
	}

	/**
	 * Determines whether the CAManager should be done cached or not
	 *
	 * @param isCached True for cached, False for not cached.
	 */
	public void setCached(boolean isCached) {
		this.isCached = isCached;
	}
}
