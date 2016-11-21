/*
 * Demoiselle Framework
 * Copyright (C) 2010 SERPRO
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

package org.demoiselle.signer.jnlp.tiny;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

public class Item {

	private final String alias;
	private final String subject;
	private final String initDate;
	private final String endDate;
	private final String issuer;

	public Item(String alias, String subject, Date initDate, Date endDate, String issuer) {
		DateFormat f = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");

		this.alias = alias;
		this.subject = this.corte(subject);
		this.initDate = f.format(initDate);
		this.endDate = f.format(endDate);
		this.issuer = this.corte(issuer);
	}

	public String getAlias() {
		return alias;
	}

	public String getSubject() {
		return subject;
	}

	public String getInitDate() {
		return initDate;
	}

	public String getEndDate() {
		return endDate;
	}

	public String getIssuer() {
		return issuer;
	}

	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer();
		buffer.append(subject);
		return buffer.toString();
	}

	private String corte(String texto) {

		int end = 0;
		end = texto.indexOf(",");
		if (end == -1)
			end = texto.length();

		String cortado = texto.substring(0, end);
		return cortado.replace("CN=", "");
	}
}
