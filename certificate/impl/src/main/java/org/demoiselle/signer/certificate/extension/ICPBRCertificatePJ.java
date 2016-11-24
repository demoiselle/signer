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

package org.demoiselle.signer.certificate.extension;

import org.demoiselle.signer.certificate.oid.OID_2_16_76_1_3_2;
import org.demoiselle.signer.certificate.oid.OID_2_16_76_1_3_3;
import org.demoiselle.signer.certificate.oid.OID_2_16_76_1_3_4;
import org.demoiselle.signer.certificate.oid.OID_2_16_76_1_3_7;

/**
 * Implemented Class for ICP-BRASIL (DOC-ICP-04) "PESSOA JURIDICA" Certificates.
 * 
 * @see ICPBRSubjectAlternativeNames
 */
public class ICPBRCertificatePJ {

	private OID_2_16_76_1_3_2 oID_2_16_76_1_3_2 = null;
	private OID_2_16_76_1_3_3 oID_2_16_76_1_3_3 = null;
	private OID_2_16_76_1_3_4 oID_2_16_76_1_3_4 = null;
	private OID_2_16_76_1_3_7 oID_2_16_76_1_3_7 = null;

	/**
	 * 
	 * @param oid1
	 *            -> 2.16.76.1.3.2 e conteudo = nome do responsavel pelo
	 *            certificado
	 * @param oid2
	 *            -> 2.16.76.1.3.3 e conteudo = Cadastro Nacional de Pessoa
	 *            Juridica (CNPJ) da pessoa juridica titular do certificado
	 * @param oid3
	 *            -> 2.16.76.1.3.4 e conteudo = nas primeiras 8 (oito) posicoes,
	 *            a data de nascimento do responsavel pelo certificado, no
	 *            formato ddmmaaaa; nas 11 (onze) posicoes subsequentes, o
	 *            Cadastro de Pessoa Fisica (CPF) do responsavel; nas 11 (onze)
	 *            posicoes subsequentes, o numero de Identificacao Social - NIS
	 *            (PIS, PASEP ou CI); nas 15 (quinze) posicoes subsequentes, o
	 *            numero do RG do responsavel; nas 6 (seis) posicoes
	 *            subsequentes, as siglas do orgao expedidor do RG e respectiva
	 *            UF
	 * 
	 * @param oid4
	 *            -> 2.16.76.1.3.7 e conteudo = nas 12 (doze) posicoes o numero
	 *            do Cadastro Especifico do INSS (CEI) da pessoa juridica
	 *            titular do certificado
	 */
	public ICPBRCertificatePJ(OID_2_16_76_1_3_2 oid1, OID_2_16_76_1_3_3 oid2, OID_2_16_76_1_3_4 oid3, OID_2_16_76_1_3_7 oid4) {
		this.oID_2_16_76_1_3_2 = oid1;
		this.oID_2_16_76_1_3_3 = oid2;
		this.oID_2_16_76_1_3_4 = oid3;
		this.oID_2_16_76_1_3_7 = oid4;
	}

	/**
	 * 
	 * @return nome do responsavel pelo certificado
	 */
	public String getNomeResponsavel() {
		return oID_2_16_76_1_3_2.getNome();
	}

	/**
	 * 
	 * @return Cadastro Nacional de Pessoa Juridica (CNPJ) da pessoa juridica
	 *         titular do certificado
	 */
	public String getCNPJ() {
		return oID_2_16_76_1_3_3.getCNPJ();
	}

	/**
	 * 
	 * @return a data de nascimento do responsavel pelo certificado (ddMMyyyy)
	 */
	public String getDataNascimento() {
		return oID_2_16_76_1_3_4.getDataNascimento();

	}

	/**
	 * 
	 * @return o numero de Identificacao Social - NIS (PIS, PASEP ou CI)
	 */
	public String getNis() {
		return oID_2_16_76_1_3_4.getNIS();
	}

	/**
	 * 
	 * @return o numero do RG do responsavel
	 */
	public String getRg() {
		return oID_2_16_76_1_3_4.getRg();
	}

	/**
	 * 
	 * @return as siglas do orgao expedidor do RG e respectiva UF
	 */
	public String getOrgaoExpedidorRg() {
		return oID_2_16_76_1_3_4.getOrgaoExpedidorRg();
	}

	/**
	 * 
	 * @return as siglas do orgao expedidor do RG e respectiva UF
	 */
	public String getUfExpedidorRg() {
		return oID_2_16_76_1_3_4.getUfExpedidorRg();
	}

	/**
	 * 
	 * @return o numero do Cadastro Especifico do INSS (CEI) da pessoa juridica
	 *         titular do certificado
	 */
	public String getCEI() {
		return oID_2_16_76_1_3_7.getCEI();
	}

}
