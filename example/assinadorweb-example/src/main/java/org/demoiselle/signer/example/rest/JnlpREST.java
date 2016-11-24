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
package org.demoiselle.signer.example.rest;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;


@Path("jnlp")
public class JnlpREST {
	
	@Context 
	HttpServletRequest httpRequest;

	@POST
	@Path("generate")
	@Produces("application/x-java-jnlp-file")
	public Response generate() {
		ResponseBuilder response = null;
		String identificador = httpRequest.getParameter("hash");
		String servico = httpRequest.getParameter("service");

		response = Response.ok(generate(identificador, servico));
		response.header("Content-type", "application/x-java-jnlp-file");
		return  response.build();
	}

	private String generate(String identificador, String servico) {
		
		String url =  httpRequest.getScheme() + "://" +  httpRequest.getServerName() + ":" 
				+  httpRequest.getServerPort() +   httpRequest.getContextPath();
		
		StringBuilder sb = new StringBuilder();
		sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n");
		sb.append("<jnlp codebase=\"").append(url).append("\" spec=\"1.0+\">\n");
		sb.append("<information>\n");
		sb.append("<title>Assinador Digital de Documentos</title>\n");
		sb.append("<vendor>Servico Federal de Processamento de Dados</vendor>\n");
		sb.append("<description>Descricao...</description>\n");
		sb.append("<homepage href=\"http://www.serpro.gov.br\"/>\n");
		sb.append("</information>\n");
		sb.append("<security>\n");
		sb.append("<all-permissions/>\n");
		sb.append("</security>\n");
		sb.append("<resources>\n");
		sb.append("<jar href=\"assinadorweb-desktop-1.1.0.jar\" main=\"true\"/>\n");
		sb.append("<jar href=\"demoiselle-certificate-core-1.1.0.jar\"/>\n");
		sb.append("<jar href=\"demoiselle-certificate-signer-1.1.0.jar\"/>\n");
		sb.append("<jar href=\"demoiselle-certificate-criptography-1.1.0.jar\"/>\n");
		sb.append("<jar href=\"demoiselle-certificate-ca-icpbrasil-1.1.0.jar\"/>\n");
		sb.append("<jar href=\"demoiselle-certificate-desktop-1.1.0.jar\"/>\n");
		sb.append("<jar href=\"bcprov-jdk15-1.45.jar\"/>\n");
		sb.append("<jar href=\"bcmail-jdk15-1.45.jar\"/>\n");
		sb.append("<property name=\"jnlp.identifier\" value=\"").append(identificador).append("\"/>\n");
		sb.append("<property name=\"jnlp.service\" value=\"").append(servico).append("\"/>\n");
		sb.append("<!-- O parametro abaixo define a classe customizada de implementacao. Se ausente, sera usada a implementacao pre-definida no componente -->").append("\n");
		sb.append("<property name=\"jnlp.myClassName\" value=\"").append("br.gov.frameworkdemoiselle.certificate.example.App").append("\"/>\n");
		sb.append("</resources>\n");
		sb.append("<application-desc main-class=\"br.gov.frameworkdemoiselle.certificate.ui.view.MainFrame\"/>\n");
		sb.append("</jnlp>");

		return sb.toString();
	}
}

