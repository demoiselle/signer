/*
 * Demoiselle Framework
 * Copyright (C) 2021 SERPRO
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

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.demoiselle.signer.core.oid.OID_2_16_76_1_3_2;
import org.demoiselle.signer.core.oid.OID_2_16_76_1_3_3;
import org.demoiselle.signer.core.oid.OID_2_16_76_1_3_4;
import org.demoiselle.signer.core.oid.OID_2_16_76_1_3_8;
import org.demoiselle.signer.core.oid.OID_2_5_29_17;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Has some "ICP-BRASIL Pessoa Juridica and Equipment" attributes
 *
 * <ul>
 *
 * <li>oid1 2.16.76.1.3.2 and content = name of the person responsible for
 * the certificate.</li>
 *
 * <li>oid2 2.16.76.1.3.3 and content= Brazilian National Registry of
 * Bussiness Entities called Cadastro Nacional de Pessoa Juridica (CNPJ),
 * if the certificate is a CNPJ.</li>
 *
 * <li>oid3 2.16.76.1.3.4 and content = In the first 8 (eight) positions,
 * the Date of birth of the person responsible for the certificate, in
 * ddmmaaaa format.</li>
 *
 * <li>In the 11 (eleven) subsequent positions, the Brazilian IRS
 * Individuals Registry number called CPF of the Responsible;</li>
 *
 * <li>In the 11 (eleven) subsequent positions, the number of
 * Brazilian Social Identification number - NIS (PIS, PASEP or CI);</li>
 *
 * <li>In the 15 (fifteen) positions Subsequent, the Brazilian ID number
 * (called RG) of the responsible for the certificate;</li>
 *
 * <li>In the six (6) positions Subsequent, the initials of the issuing
 * agency of the ID (RG) and its UF (Initials for a Brasilian state).</li>
 *
 * <li>oid4 2.16.76.1.3.8 and content = Corporate name in the the Brazilian
 * IRS's Bussiness Company Registry Number caled CNPJ without abbreviations,
 * if its is an equipment certificate.</li>
 *
 * </ul>
 */
public class ICPBRCertificateEquipment {

	private OID_2_16_76_1_3_2 oID_2_16_76_1_3_2 = null;
	private OID_2_16_76_1_3_3 oID_2_16_76_1_3_3 = null;
	private OID_2_16_76_1_3_4 oID_2_16_76_1_3_4 = null;
	private OID_2_16_76_1_3_8 oID_2_16_76_1_3_8 = null;
	private OID_2_5_29_17 oID_2_5_29_17 = null;
	private String serialNumber = null;

	private static final Logger logger = LoggerFactory.getLogger(ICPBRCertificateEquipment.class);

	/**
	 * @param oid1 2.16.76.1.3.2 and content = name of the person responsible for
	 *             the certificate
	 * @param oid2 2.16.76.1.3.3 and content= Brazilian National Registry of Bussiness Entities called
	 *             Cadastro Nacional de Pessoa Juridica (CNPJ), if the certificate is a CNPJ
	 * @param oid3 2.16.76.1.3.4 and content = In the first 8 (eight) positions, the
	 *             Date of birth of the person responsible for the certificate, in ddmmaaaa format;
	 *             In the 11 (eleven) subsequent positions, the Brazilian IRS Individuals Registry number called CPF of the
	 *             Responsible; In the 11 (eleven) subsequent positions, the number of
	 *             Brazilian Social Identification number - NIS (PIS, PASEP or CI); In the 15 (fifteen) positions
	 *             Subsequent, the Brazilian ID number (called RG) of the responsible for the certificate; In the six (6) positions
	 *             Subsequent, the initials of the issuing agency of the ID (RG) and its UF (Initials for a Brasilian state).
	 * @param oid4 2.16.76.1.3.8 and content = Corporate name in the the Brazilian IRS's Bussiness Company Registry Number caled CNPJ without abbreviations,
	 *             if its is an equipment certificate
	 * @param oid5 fake.
	 * @param serialNumber fake
	 */
	public ICPBRCertificateEquipment(OID_2_16_76_1_3_2 oid1, OID_2_16_76_1_3_3 oid2, OID_2_16_76_1_3_4 oid3, OID_2_16_76_1_3_8 oid4,
									 OID_2_5_29_17 oid5, String serialNumber) {
		this.oID_2_16_76_1_3_2 = oid1;
		this.oID_2_16_76_1_3_3 = oid2;
		this.oID_2_16_76_1_3_4 = oid3;
		this.oID_2_16_76_1_3_8 = oid4;
		this.oID_2_5_29_17 = oid5;
		this.serialNumber = serialNumber;
	}

	/**
	 * @return string Name of the person responsible for the certificate
	 */
	public String getResponsibleName() {
		if (oID_2_16_76_1_3_2 != null) return oID_2_16_76_1_3_2.getName();
		else return null;
	}

	/**
	 * @return nome Corporate name in the the Brazilian IRS's Bussiness Company Registry Number
	 */
	public String getCorporateName() {
		if (oID_2_16_76_1_3_8 != null) return oID_2_16_76_1_3_8.getName();
		else return null;
	}

	/**
	 * @return the Brazilian IRS's Bussiness Company Registry Number called CNPJ
	 */
	public String getCNPJ() {
		String cnpj = "";
		if (oID_2_16_76_1_3_3 != null) {
			cnpj = oID_2_16_76_1_3_3.getCNPJ();
		}
		if (cnpj.isEmpty()) cnpj = getSerialNumber();
		return cnpj;
	}

	/**
	 * @return Date of birth of the responsible for the certificate
	 */
	public Date getBirthDate() {
		if (oID_2_16_76_1_3_4 != null) {
			try {
				SimpleDateFormat sdf = new SimpleDateFormat("ddMMyyyy");
				return sdf.parse(oID_2_16_76_1_3_4.getBirthDate());
			} catch (ParseException e) {
				logger.error(e.getMessage());
				return null;
			}
		} else {
			return null;
		}

	}

	/**
	 * @return Brazilian Social Identification number of the responsible - initials are: NIS
	 */
	public String getNis() {

		if (oID_2_16_76_1_3_4 != null) return oID_2_16_76_1_3_4.getNIS();
		else return null;
	}

	/**
	 * @return the Brazilian ID number (called RG) of the responsible for the certificate
	 */
	public String getRg() {
		if (oID_2_16_76_1_3_4 != null) return oID_2_16_76_1_3_4.getRg();
		else return null;
	}

	/**
	 * @return the initials of the issuing agency of the Brazilian ID (RG)
	 */
	public String getIssuingAgencyRg() {
		if (oID_2_16_76_1_3_4 != null) return oID_2_16_76_1_3_4.getIssuingAgencyRg();
		else return null;
	}

	/**
	 * @return Initials for a Brasilian state(UF) of the issuing agency of the ID (RG)
	 */
	public String getUfIssuingAgencyRg() {
		if (oID_2_16_76_1_3_4 != null) return oID_2_16_76_1_3_4.getUfIssuingAgencyRg();
		else return null;
	}

	public String getDNS() {
		if (oID_2_5_29_17 != null) return oID_2_5_29_17.getData();
		else return null;
	}

	public String getSerialNumber() {
		return serialNumber;
	}
}
