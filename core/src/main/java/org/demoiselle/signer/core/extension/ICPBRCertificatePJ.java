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

	/**
	 * @param oid1 -&gt; 2.16.76.1.3.2 and content = Name of the person responsible for the certificate
	 * @param oid2 -&gt; 2.16.76.1.3.3 and content = the Brazilian IRS's Bussiness Company Registry Number
	 *             called CNPJ (Cadastro Nacional de Pessoa Juridica)
	 * @param oid3 -&gt; 2.16.76.1.3.4 and content = In the first 8 (eight) positions,
	 *             Date of birth of the person responsible for the certificate, in ddMMyyyy format,
	 *             In the eleven (11) subsequent positions, the Brazilian IRS Individuals Registry number
	 *             called CPF (Cadastro de Pessoa Fisica) of the responsible for the certificate;
	 *             In the next eleven (11)positions, Brazilian Social Identification number -
	 *             initials are: NIS (PIS, PASEP or CI) of the responsible;
	 *             In the 15 (fifteen) subsequent positions, the Brazilian ID number (called RG)
	 *             of the responsible for the certificate; In the 6 (six) subsequent positions,
	 *             the initials of the issuing agency of the ID (RG) and
	 *             the Initials for a Brasilian state(UF) of the issuing agency of the ID (RG)
	 * @param oid4 -&gt; 2.16.76.1.3.7 and content = In the 12 (twelve) positions the number of Specific Registry (called CEI), on
	 *             Brazilian National Institute of Social Security,  of the bussines company holding the certificate
	 */
	public ICPBRCertificatePJ(OID_2_16_76_1_3_2 oid1, OID_2_16_76_1_3_3 oid2, OID_2_16_76_1_3_4 oid3, OID_2_16_76_1_3_7 oid4) {
		this.oID_2_16_76_1_3_2 = oid1;
		this.oID_2_16_76_1_3_3 = oid2;
		this.oID_2_16_76_1_3_4 = oid3;
		this.oID_2_16_76_1_3_7 = oid4;
	}

	/**
	 * @return Name of the person responsible for the certificate
	 */
	public String getResponsibleName() {
		return oID_2_16_76_1_3_2.getName();
	}

	/**
	 * @return CPF (a Brazilian document ) of the person responsible for the certificate
	 */
	public String getResponsibleCPF() {
		return oID_2_16_76_1_3_4.getCPF();
	}

	/**
	 * @return Corporate name in the the Brazilian IRS's Bussiness Company Registry Number called CNPJ
	 */
	public String getCNPJ() {
		return oID_2_16_76_1_3_3.getCNPJ();
	}

	/**
	 * @return Date of birth of the person responsible for the certificate in ddMMyyyy format
	 */
	public String getBirthDate() {
		return oID_2_16_76_1_3_4.getBirthDate();

	}

	/**
	 * @return Brazilian Social Identification number of the responsible - initials are: NIS
	 */
	public String getNis() {
		return oID_2_16_76_1_3_4.getNIS();
	}

	/**
	 * @return the Brazilian ID number (called RG) of the responsible for the certificate
	 */
	public String getRg() {
		return oID_2_16_76_1_3_4.getRg();
	}

	/**
	 * @return initials of the issuing agency of the Brazilian ID (RG)
	 */
	public String getIssuingAgencyRg() {
		return oID_2_16_76_1_3_4.getIssuingAgencyRg();
	}

	/**
	 * @return Initials for a Brasilian state(called UF) of the issuing agency of the ID (RG)
	 */
	public String getUfIssuingAgencyRg() {
		return oID_2_16_76_1_3_4.getUfIssuingAgencyRg();
	}

	/**
	 * @return number of Specific Registry (called CEI), on  Brazilian National Institute of Social Security,
	 * of the bussines company holding the certificate
	 */
	public String getCEI() {
		return oID_2_16_76_1_3_7.getCEI();
	}

}
