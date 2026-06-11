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

package org.demoiselle.signer.core.extension;

import org.demoiselle.signer.core.oid.OID_2_16_76_1_3_2;
import org.demoiselle.signer.core.oid.OID_2_16_76_1_3_3;
import org.demoiselle.signer.core.oid.OID_2_16_76_1_3_4;
import org.demoiselle.signer.core.oid.OID_2_16_76_1_3_7;

/**
 * Implemented Class for ICP-BRASIL (DOC-ICP-04)
 * "PESSOA JURIDICA" Certificates.
 *
 * @see ICPBRSubjectAlternativeNames
 */
public class ICPBRCertificatePJ {

	private OID_2_16_76_1_3_2 oID_2_16_76_1_3_2;
	private OID_2_16_76_1_3_3 oID_2_16_76_1_3_3;
	private OID_2_16_76_1_3_4 oID_2_16_76_1_3_4;
	private OID_2_16_76_1_3_7 oID_2_16_76_1_3_7;
	private String serialNumber;

	public ICPBRCertificatePJ(OID_2_16_76_1_3_2 oid1, OID_2_16_76_1_3_3 oid2, OID_2_16_76_1_3_4 oid3, OID_2_16_76_1_3_7 oid4, String serialNumber) {
		this.oID_2_16_76_1_3_2 = oid1;
		this.oID_2_16_76_1_3_3 = oid2;
		this.oID_2_16_76_1_3_4 = oid3;
		this.oID_2_16_76_1_3_7 = oid4;
		this.serialNumber = serialNumber;
	}

	public ICPBRCertificatePJ(OID_2_16_76_1_3_2 oid1, OID_2_16_76_1_3_3 oid2, OID_2_16_76_1_3_4 oid3, OID_2_16_76_1_3_7 oid4) {
		this(oid1, oid2, oid3, oid4, null);
	}

	/**
	 * @return Name of the person responsible for the certificate
	 */
	public String getResponsibleName() {
		return oID_2_16_76_1_3_2 != null ? oID_2_16_76_1_3_2.getName() : null;
	}

	/**
	 * @return CPF (a Brazilian document ) of the person responsible for the certificate
	 */
	public String getResponsibleCPF() {
		return oID_2_16_76_1_3_4 != null ? oID_2_16_76_1_3_4.getCPF() : null;
	}

	/**
	 * @return Corporate name in the the Brazilian IRS's Bussiness Company Registry Number called CNPJ
	 */
	public String getCNPJ() {
		if (serialNumber != null && !serialNumber.isEmpty()) {
			return serialNumber;
		}
		if (oID_2_16_76_1_3_3 != null) {
			return oID_2_16_76_1_3_3.getCNPJ();
		}
		return null;
	}

	/**
	 * @return Date of birth of the person responsible for the certificate in ddMMyyyy format
	 */
	public String getBirthDate() {
		return oID_2_16_76_1_3_4 != null ? oID_2_16_76_1_3_4.getBirthDate() : null;
	}

	/**
	 * @return Brazilian Social Identification number of the responsible - initials are: NIS
	 */
	public String getNis() {
		return oID_2_16_76_1_3_4 != null ? oID_2_16_76_1_3_4.getNIS() : null;
	}

	/**
	 * @return the Brazilian ID number (called RG) of the responsible for the certificate
	 */
	public String getRg() {
		return oID_2_16_76_1_3_4 != null ? oID_2_16_76_1_3_4.getRg() : null;
	}

	/**
	 * @return initials of the issuing agency of the Brazilian ID (RG)
	 */
	public String getIssuingAgencyRg() {
		return oID_2_16_76_1_3_4 != null ? oID_2_16_76_1_3_4.getIssuingAgencyRg() : null;
	}

	/**
	 * @return Initials for a Brasilian state(called UF) of the issuing agency of the ID (RG)
	 */
	public String getUfIssuingAgencyRg() {
		return oID_2_16_76_1_3_4 != null ? oID_2_16_76_1_3_4.getUfIssuingAgencyRg() : null;
	}

	/**
	 * @return number of Specific Registry (called CEI), on  Brazilian National Institute of Social Security,
	 * of the bussines company holding the certificate
	 */
	public String getCEI() {
		return oID_2_16_76_1_3_7 != null ? oID_2_16_76_1_3_7.getCEI() : null;
	}

}
