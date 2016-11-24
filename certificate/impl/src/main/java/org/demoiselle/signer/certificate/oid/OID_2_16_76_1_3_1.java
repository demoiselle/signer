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
package org.demoiselle.signer.certificate.oid;

/**
 * Classe OID 2.16.76.1.3.1 <br>
 * <br>
 * Possui alguns atributos de pessoa fisica: <br>
 * <b>*</b> Data de nascimento do titular "DDMMAAAA" <br>
 * <b>*</b> Cadastro de pessoa fisica (CPF) do titular <br>
 * <b>*</b> Numero de Identidade Social - NIS (PIS, PASEP ou CI) <br>
 * <b>*</b> Numero do Registro Geral (RG) do titular <br>
 * <b>*</b> Sigla do orgao expedidor do RG <br>
 * <b>*</b> UF do orgao expedidor do RG <br>
 * <b>*</b> Conforme:<br>
 * nas primeiras 8 (oito) posicoes, a data de nascimento do titular, no formato
 * ddmmaaa; nas 11 (onze) posicoes subsequentes, o Cadastro de Pessoa Fisica
 * (CPF) do titular; nas 11 (onze) posicoes subsequentes, o numero de
 * Identificacao Social - NIS (PIS, PASEP ou CI); nas 15 (quinze) posicoes
 * subsequentes, o numero do Registro Geral - RG do titular; nas 6 (seis)
 * posicoes subsequentes, as siglas do orgao expedidor do RG e respectiva UF
 *
 */
public class OID_2_16_76_1_3_1 extends OIDGeneric {

    public static final String OID = "2.16.76.1.3.1";

    protected static final Object CAMPOS[] = {"dtNascimento", 8, "cpf", 11, "nis", 11, "rg", 15, "orgaoUfExpedidor", 6};

    public OID_2_16_76_1_3_1() {
    }

    @Override
    public void initialize() {
        super.initialize(CAMPOS);
    }

    /**
     *
     * @return a data de nascimento do titular
     */
    public String getDataNascimento() {
        return properties.get("dtNascimento");
    }

    /**
     *
     * @return numero do Cadastro de Pessoa Fisica (CPF) do titular;
     */
    public String getCPF() {
        return properties.get("cpf");
    }

    /**
     *
     * @return o numero de Identificacao Social - NIS (PIS, PASEP ou CI)
     */
    public String getNIS() {
        return properties.get("nis");
    }

    /**
     *
     * @return numero do Registro Geral - RG do titular
     */
    public String getRg() {
        return properties.get("rg");
    }

    /**
     *
     * @return as siglas do orgao expedidor do RG
     */
    public String getOrgaoExpedidorRg() {
        String s = properties.get("orgaoUfExpedidor").trim();
        int len = s.trim().length();
        String retorno = null;
        if (len > 0) {
            retorno = s.substring(0, len - 2);
        }
        return retorno;
    }

    /**
     *
     * @return a UF do orgao expedidor do RG
     */
    public String getUfExpedidorRg() {
        String s = properties.get("orgaoUfExpedidor").trim();
        int len = s.trim().length();
        String retorno = null;
        if (len > 0) {
            retorno = s.substring(len - 2, len);
        }
        return retorno;
    }

}
