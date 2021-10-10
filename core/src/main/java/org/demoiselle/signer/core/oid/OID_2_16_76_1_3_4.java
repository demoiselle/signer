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
 * Has some ICP-BRASIL's "Pessoa Juridica" and Equipment attributes<br>
 * <b>*</b> Date of birth of the person responsible for the certificate, in ddmmaaaa format <br>
 * <b>*</b> the Brazilian IRS Individuals Registry number called CPF (Cadastro de Pessoa Fisica) of the
 * Responsible <br>
 * <b>*</b>Brazilian Social Identification number - intials are: NIS (PIS, PASEP or CI)of the responsible <br>
 * <b>*</b> the Brazilian ID number (called RG) of the responsible for the certificate <br>
 * <b>*</b> the initials of the issuing agency of the ID (RG) <br>
 * <b>*</b> Initials for a Brasilian state(UF) of the issuing agency of the ID (RG) <br>
 */
public class OID_2_16_76_1_3_4 extends OIDGeneric {

	public static final String OID = "2.16.76.1.3.4";

	protected static final Object FIELDS[] = {"birthDate", (int) 8, "cpf", (int) 11, "nis", (int) 11, "rg", (int) 15, "UfIssuingAgencyRg", (int) 6};

	public OID_2_16_76_1_3_4() {
	}

	@Override
	public void initialize() {
		super.initialize(FIELDS);
	}

	/**
	 * @return Date of birth of the person responsible for the certificate in ddMMyyyy format
	 */
	public String getBirthDate() {
		return properties.get("birthDate");
	}

	/**
	 * @return the Brazilian IRS Individuals Registry number called CPF (Cadastro de Pessoa Fisica) of the
	 * Responsible
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
	 * @return the Brazilian ID number (called RG) of the responsible for the certificate
	 */
	public String getRg() {
		return properties.get("rg");
	}

	/**
	 * @return initials of the issuing agency of the Brazilian ID (RG)
	 */
	public String getIssuingAgencyRg() {

		String s = properties.get("UfIssuingAgencyRg").trim();
		int len = s.trim().length();
		String ret = null;
		if (len > 0) {
			ret = s.substring(0, len - 2);
		}
		return ret;
	}

	/**
	 * @return Initials for a Brasilian state(UF) of the issuing agency of the ID (RG)
	 */
	public String getUfIssuingAgencyRg() {
		String s = properties.get("UfIssuingAgencyRg").trim();
		int len = s.trim().length();
		String ret = null;
		if (len > 0) {
			ret = s.substring(len - 2, len);
		}
		return ret;
	}
}
