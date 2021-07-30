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

package org.demoiselle.signer.policy.impl.xades.xml;

import java.io.InputStream;
import java.util.List;

import org.demoiselle.signer.policy.impl.xades.XMLSignatureInformations;
import org.w3c.dom.Document;

/**
 * 
 * @author Emerson Sachio Saito <emerson.saito@serpro.gov.br>
 *
 */
public interface Checker {
	
	
	abstract public boolean check(Document doc);
	
	abstract public boolean check(String xmlAsString);
	
	abstract public boolean check(boolean isFileLocation, String xmlSignedFile); 
	
	abstract public boolean check(byte[] docData);
	
	abstract public boolean check(InputStream isXMLFile);

	abstract public boolean check(String signedContentFileName, String signatureFileName);
	
	abstract public boolean check(byte[] signedContent, byte[] signature);
	
	abstract public boolean check(InputStream isContent, InputStream isXMLSignature);
	
	
	abstract public boolean checkHash(byte[] contentcHash, Document xmlSignature);
	
	abstract public boolean checkHash(byte[] contentcHash, byte[] xmlSignature);
	
	abstract public boolean checkHash(byte[] contentHash, String xmlSignature);
	
	abstract public boolean checkHash(InputStream isContent, Document xmlSignature);
	
	abstract public boolean checkHash(InputStream isContent, InputStream isXMLSignature);
	
	abstract public boolean checkHash(InputStream isContent, String xmlSignature);
	
	
	
	
	abstract public List<XMLSignatureInformations> getSignaturesInfo(); 
	
	
}
