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
 * Implemented Class for ICP-BRASIL (DOC-ICP-04) "PESSOA FISICA" Certificates.
 * 
 * @see ICPBRSubjectAlternativeNames
 */

public class ICPBRCertificatePF {

	private OID_2_16_76_1_3_1 oID_2_16_76_1_3_1 = null;
	private OID_2_16_76_1_3_5 oID_2_16_76_1_3_5 = null;
	private OID_2_16_76_1_3_6 oID_2_16_76_1_3_6 = null;

	/**
	 * 
	 * @param oid1
	 *            -> 2.16.76.1.3.1 e conteudo = nas primeiras 8 (oito) posicoes,
	 *            a data de nascimento do titular, no formato ddmmaaaa; nas 11
	 *            (onze) posicoes subsequentes, o Cadastro de Pessoa Fisica
	 *            (CPF) do titular; nas 11 (onze) posicoes subsequentes, o
	 *            numero de Identificacao Social - NIS (PIS, PASEP ou CI); nas
	 *            15 (quinze) posicoes subsequentes, o numero do Registro Geral
	 *            - RG do titular; nas 6 (seis) posicoes subsequentes, as siglas
	 *            do orgao expedidor do RG e respectiva UF.
	 * 
	 * @param oid2
	 *            -> 2.16.76.1.3.5 e conteudo = nas primeiras 12 (onze)
	 *            posicoes, o numero de inscricao do Titulo de Eleitor; nas 3
	 *            (tres) posicoes subsequentes, a Zona Eleitoral; nas 4 (quatro)
	 *            posicoes seguintes, a Secao; nas 22 (vinte e duas) posicoes
	 *            subsequentes, o municipio e a UF do Titulo de Eleitor
	 * 
	 * @param oid3
	 *            -> 2.16.76.1.3.6 e conteudo = nas 12 (doze) posicoes o numero
	 *            do Cadastro Especifico do INSS (CEI) da pessoa fisica titular
	 *            do certificado
	 */
	public ICPBRCertificatePF(OID_2_16_76_1_3_1 oid1, OID_2_16_76_1_3_5 oid2, OID_2_16_76_1_3_6 oid3) {
		this.oID_2_16_76_1_3_1 = oid1;
		this.oID_2_16_76_1_3_5 = oid2;
		this.oID_2_16_76_1_3_6 = oid3;
	}

	/**
	 * 
	 * @return o numero do Cadastro de Pessoa Fisica (CPF) do titular
	 */
	public String getCPF() {
		return oID_2_16_76_1_3_1.getCPF();
	}

	/**
	 * 
	 * @return data de nascimento do titular
	 */
	public String getDataNascimento() {
		return oID_2_16_76_1_3_1.getDataNascimento();
	}

	/**
	 * 
	 * @return o numero de Identificacao Social - NIS (PIS, PASEP ou CI)
	 */
	public String getNis() {
		return oID_2_16_76_1_3_1.getNIS();
	}

	/**
	 * 
	 * @return o numero do Registro Geral - RG do titular
	 */
	public String getRg() {
		return oID_2_16_76_1_3_1.getRg();
	}

	/**
	 * 
	 * @return as siglas do orgao expedidor do RG
	 */
	public String getOrgaoExpedidorRg() {
		return oID_2_16_76_1_3_1.getOrgaoExpedidorRg();
	}

	/**
	 * 
	 * @return a UF do orgao expedidor do RG
	 */
	public String getUfExpedidorRg() {
		return oID_2_16_76_1_3_1.getUfExpedidorRg();
	}

	/**
	 * 
	 * @return o numero de inscricao do Titulo de Eleitor
	 */
	public String getTituloEleitor() {
		return oID_2_16_76_1_3_5.getTitulo();
	}

	/**
	 * 
	 * @return o numero da Secao do Titulo de Eleitor
	 */
	public String getSecaoTituloEleitor() {
		return oID_2_16_76_1_3_5.getSecao();
	}

	/**
	 * 
	 * @return numero da Zona Eleitoral do Titulo de Eleitor
	 */
	public String getZonaTituloEleitor() {
		return oID_2_16_76_1_3_5.getZona();
	}

	/**
	 * 
	 * @return o municipio e a UF do Titulo de Eleitor
	 * 
	 *         public String getMunicipioUfTituloEleitor(){ return
	 *         oID_2_16_76_1_3_5.getMunicipioUf(); }
	 */

	/**
	 * 
	 * @return o municipio do Titulo de Eleitor
	 */
	public String getMunicipioTituloEleitor() {
		return oID_2_16_76_1_3_5.getMunicipioTitulo();
	}

	/**
	 * 
	 * @return a UF do Titulo de Eleitor
	 */
	public String getUfTituloEleitor() {
		return oID_2_16_76_1_3_5.getUFTitulo();
	}

	/**
	 * 
	 * @return o numero do Cadastro Especifico do INSS (CEI) da pessoa fisica
	 *         titular do certificado
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
