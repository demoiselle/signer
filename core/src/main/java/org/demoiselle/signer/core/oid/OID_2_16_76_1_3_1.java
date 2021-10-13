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
 * * Has some "ICP-BRASIL Pessoa Fisica" attributes<br>
 * <b> * </b> Date of birth of the holder on "DDMMAAAA" format<br>
 * <B> * </b> The Brazilian IRS Individuals Registry called CPF <br>
 * <B> * </b> Brazilian Social Identity Number - NIS (PIS, PASEP or CI) <br>
 * <B> * </b> the Brazilian ID number called RG <br>
 * <B> * </b> the initials of the issuing agency of the ID (RG) <br>
 * <B> * </b> UF (Initials for a Brasilian state) of the issuing agency of the RG <br>
 */
public class OID_2_16_76_1_3_1 extends OIDGeneric {

	public static final String OID = "2.16.76.1.3.1";

	protected static final Object FIELDS[] = {"birthDate", 8, "cpf", 11, "nis", 11, "rg", 15, "UfIssuingAgencyRg", 6};

	public OID_2_16_76_1_3_1() {
	}

	@Override
	public void initialize() {
		super.initialize(FIELDS);
	}

	/**
	 * @return Date of birth of holder the certificate in ddMMyyyy format
	 */
	public String getBirthDate() {
		return properties.get("birthDate");
	}

	/**
	 * @return the Brazilian IRS Individuals Registry number called CPF
	 */
	public String getCPF() {
		return properties.get("cpf");
	}

	/**
	 * @return Brazilian Social Identification number of the responsible - initials are: NIS
	 */
	public String getNIS() {
		return properties.get("nis");
	}

	/**
	 * @return the Brazilian ID number (called RG), of the certificate's holder
	 */
	public String getRg() {
		return properties.get("rg");
	}

	/**
	 * @return the initials of the issuing agency of the Brazilian ID (RG)
	 */
	public String getIssuingAgencyRg() {
		String s = properties.get("UfIssuingAgencyRg").trim();
		int len = s.trim().length();
		String retIssuingAgencyRg = null;
		if (len > 0) {
			retIssuingAgencyRg = s.substring(0, len - 2);
		}
		return retIssuingAgencyRg;
	}

	/**
	 * @return Initials for a Brasilian state(UF) of the issuing agency of the ID (RG)
	 */
	public String getUfIssuingAgencyRg() {
		String s = properties.get("UfIssuingAgencyRg").trim();
		int len = s.trim().length();
		String retUfIssuingAgencyRg = null;
		if (len > 0) {
			retUfIssuingAgencyRg = s.substring(len - 2, len);
		}
		return retUfIssuingAgencyRg;
	}
}
