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

package org.demoiselle.signer.core.oid;

/**
 * Classe OID 2.16.76.1.3.5 <br>
 * <br>
 * * Has some "ICP-BRASIL Pessoa Fisica" attributes<br>
 * <b>*</b> Number of Electoral document <br>
 * <b>*</b> Number of Zone of Electoral document <br>
 * <b>*</b> Number Section of  Electoral document <br>
 * <b>*</b> City of  Electoral document <br>
 * <b>*</b> UF (Initials for a Brasilian state) of Electoral document<br>
 */
public class OID_2_16_76_1_3_5 extends OIDGeneric {

	public static final String OID = "2.16.76.1.3.5";

	protected static final Object FIELDS[] = {"electoralDocument", (int) 12, "zone", (int) 3, "section", (int) 4, "cityUF", (int) 22};

	public OID_2_16_76_1_3_5() {
	}

	@Override
	public void initialize() {
		super.initialize(FIELDS);
	}

	/**
	 * @return String that contains a number (whith size = 12) of the Brazilian Electoral Document  (Titulo de Eleitor)
	 */
	public String getElectoralDocument() {
		return properties.get("electoralDocument");
	}

	/**
	 * @return String that contains a number (with size = 3) Section of  Electoral document
	 */
	public String getZone() {
		return properties.get("zone");
	}

	/**
	 * @return String that contains a number (with size = 4) Section of  Electoral document
	 */
	public String getSection() {
		return properties.get("section");
	}

	/**
	 * @return Name of City of  Electoral document
	 */
	public String getCityUF() {
		String s = properties.get("cityUF").trim();
		int len = s.trim().length();
		String ret = null;
		if (len > 0) {
			ret = s.substring(0, len - 2);
		}
		return ret;

	}

	/**
	 * @return String UF (Initials for a Brasilian state) of Electoral document
	 */
	public String getUFDocument() {
		String s = properties.get("cityUF").trim();
		int len = s.trim().length();
		String ret = null;
		if (len > 0) {
			ret = s.substring(len - 2, len);
		}
		return ret;
	}
}
