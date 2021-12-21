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

import org.demoiselle.signer.core.oid.OID_2_16_76_1_3_1;
import org.demoiselle.signer.core.oid.OID_2_16_76_1_3_5;
import org.demoiselle.signer.core.oid.OID_2_16_76_1_3_6;

/**
 * Implemented Class for ICP-BRASIL (DOC-ICP-04)
 * "PESSOA FISICA" Certificates.
 *
 * @see ICPBRSubjectAlternativeNames
 */

public class ICPBRCertificatePF {

	private OID_2_16_76_1_3_1 oID_2_16_76_1_3_1;
	private OID_2_16_76_1_3_5 oID_2_16_76_1_3_5;
	private OID_2_16_76_1_3_6 oID_2_16_76_1_3_6;

	/**
	 * @param oid1 -&gt; 2.16.76.1.3.1 and content = In the first 8 (eight) positions, the
	 *             Date of birth of the holder for the certificate, in ddmmaaaa format;
	 *             In the 11 (eleven) subsequent positions, the Brazilian IRS Individuals Registry number called CPF of the
	 *             holder; In the 11 (eleven) subsequent positions, the number of
	 *             Brazilian Social Identification number - NIS (PIS, PASEP or CI); In the 15 (fifteen) positions
	 *             Subsequent, the Brazilian ID number (called RG) of the responsible for the certificate; In the six (6) positions
	 *             Subsequent, the initials of the issuing agency of the ID (RG) and its UF (Initials for a Brazilian state).
	 * @param oid2 -&gt; 2.16.76.1.3.5 and content = In the first 12 (eleven)
	 *             positions, the number of the Electoral document; In 3
	 *             (Three) subsequent positions, the Electoral document Zone; In the four (4)
	 *             following positions, the Section of Electoral document; In the twenty-two (22)
	 *             Subsequent  positions, the name of City and  and its UF (Initials for a Brazilian state) of the Electoral Document.
	 * @param oid3 -&gt; 2.16.76.1.3.6 and content = In the 12 (twelve) positions, the number of the registry
	 *             on Brazilian National Social Security Institute (INSS) called CEI .
	 */

	public ICPBRCertificatePF(OID_2_16_76_1_3_1 oid1, OID_2_16_76_1_3_5 oid2, OID_2_16_76_1_3_6 oid3) {
		this.oID_2_16_76_1_3_1 = oid1;
		this.oID_2_16_76_1_3_5 = oid2;
		this.oID_2_16_76_1_3_6 = oid3;
	}

	/**
	 * @return the Brazilian IRS Individuals Registry number called CPF
	 */
	public String getCPF() {
		return oID_2_16_76_1_3_1.getCPF();
	}

	/**
	 * @return Date of birth of the responsible for the certificate
	 */
	public String getBirthDate() {
		return oID_2_16_76_1_3_1.getBirthDate();
	}

	/**
	 * @return Brazilian Social Identification number of the responsible - initials are: NIS
	 */
	public String getNis() {
		return oID_2_16_76_1_3_1.getNIS();
	}

	/**
	 * @return the Brazilian ID number (called RG), of the certificate's holder
	 */
	public String getRg() {
		return oID_2_16_76_1_3_1.getRg();
	}

	/**
	 * @return the initials of the issuing agency of the Brazilian ID (RG)
	 */
	public String getIssuingAgencyRg() {
		return oID_2_16_76_1_3_1.getIssuingAgencyRg();
	}

	/**
	 * @return Initials for a Brasilian state(UF) of the issuing agency of the ID (RG)
	 */
	public String getUfIssuingAgencyRg() {
		return oID_2_16_76_1_3_1.getUfIssuingAgencyRg();
	}

	/**
	 * @return String that contains a number (with size = 12) of the Brazilian Electoral Document (Titulo Eleitor)
	 */
	public String getElectoralDocument() {
		return oID_2_16_76_1_3_5.getElectoralDocument();
	}

	/**
	 * @return String that contains a number (with size = 4) Section of  Electoral document
	 */
	public String getSectionElectoralDocument() {
		return oID_2_16_76_1_3_5.getSection();
	}

	/**
	 * @return String that contains a number (with size = 3) Section of  Electoral document
	 */
	public String getZoneElectoralDocument() {
		return oID_2_16_76_1_3_5.getZone();
	}

	/**
	 * @return o municipio e a UF do Titulo de Eleitor
	 * <p>
	 * public String getMunicipioUfTituloEleitor(){ return
	 * oID_2_16_76_1_3_5.getMunicipioUf(); }
	 * @return Name of City of  Electoral document
	 */
	public String getCityElectoralDocument() {
		return oID_2_16_76_1_3_5.getCityUF();
	}

	/**
	 * @return Initials for a Brasilian state  of Electoral document
	 */
	public String getUFElectoralDocument() {
		return oID_2_16_76_1_3_5.getUFDocument();
	}

	/**
	 * @return Brazilian Social Identification Number (INSS-CEI) of the holder of certificate
	 */
	public String getCEI() {
		return oID_2_16_76_1_3_6.getCEI();
	}

	/*
	 * TODO - Campo opcional e nao obrigatorio campos otherName, não
	 * obrigatórios, contendo: OID = 2.16.76.1.4.n e conteúdo = de tamanho
	 * variavel correspondente ao número de habilitação ou identificação
	 * profissional emitido por conselho de classe ou órgão competente. A AC
	 * Raiz, por meio do documento ATRIBUICAO DE OID NA ICPBRASIL [2]
	 * regulamentara a correspondência de cada conselho de classe ou órgão
	 * competente ao conjunto de OID acima definido.
	 */

}
