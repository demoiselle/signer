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

package org.demoiselle.signer.signature.core.oid;

/**
 * Classe OID 2.16.76.1.3.5 <br>
 * <br>
 * Possui alguns atributos de pessoa fisica: <br>
 * <b>*</b> Numero de inscricao do Titulo de Eleitor <br>
 * <b>*</b> Zona Eleitoral <br>
 * <b>*</b> Secao <br>
 * <b>*</b> Municipio do titulo <br>
 * <b>*</b> UF do titulo <br>
 * 
 */
public class OID_2_16_76_1_3_5 extends OIDGeneric {

	public static final String OID = "2.16.76.1.3.5";

	protected static final Object FIELDS[] = { "titulo", (int) 12, "zona", (int) 3, "secao", (int) 4, "municipioUf", (int) 22 };

	public OID_2_16_76_1_3_5() {
	}

	@Override
	public void initialize() {

		super.initialize(FIELDS);

	}

	/**
	 * 
	 * @return String de 12 posicoes com o numero do Titulo de eleitor
	 */
	public String getTitulo() {
		return properties.get("titulo");
	}

	/**
	 * 
	 * @return String de 3 posicoes com o numero da zona eleitoral
	 */
	public String getZona() {
		return properties.get("zona");
	}

	/**
	 * 
	 * @return String de 4 posicoes com o numero da secao eleitoral
	 */
	public String getSecao() {
		return properties.get("secao");
	}

	/**
	 * 
	 * @return String com o nome do municipio
	 */
	public String getMunicipioTitulo() {
		String s = properties.get("municipioUf").trim();
		int len = s.trim().length();
		String ret = null;
		if (len > 0) {
			ret = s.substring(0, len - 2);
		}
		return ret;

	}

	/**
	 * 
	 * @return String com a UF correspondente.
	 */
	public String getUFTitulo() {
		String s = properties.get("municipioUf").trim();
		int len = s.trim().length();
		String ret = null;
		if (len > 0) {
			ret = s.substring(len - 2, len);
		}
		return ret;
	}

}
