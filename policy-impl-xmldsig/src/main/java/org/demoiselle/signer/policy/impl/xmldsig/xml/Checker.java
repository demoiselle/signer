/*
 * Demoiselle Framework
 * Copyright (C) 2025 SERPRO
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

package org.demoiselle.signer.policy.impl.xmldsig.xml;

import java.util.List;

import org.demoiselle.signer.policy.impl.xmldsig.XMLSignatureInformations;
import org.demoiselle.signer.policy.impl.xmldsig.XMLSignerException;


/**
 * @author Eduardo &lt;edumg80@gmail.com&gt;
 */
public interface Checker {

	/**
	 * Verify signature from File Name and location. (example: check(true,"/tmp/file.xml");
	 *
	 * @param isFileLocation true if the next parameter is a path and name for XML file
	 * @param xmlSignedFile  path and name for XML file
	 * @return fake.
	 * @throws XMLSignerException 
	 */
	boolean check(boolean isFileLocation, String xmlSignedFile) throws XMLSignerException;
	
	/**
	 * * XML signature validation using byte[] data. The content must contains both content and signature
	 *
	 * @param docData fake.
	 * @return fake.
	 * @throws XMLSignerException 
	 */	
	boolean check(byte[] docData) throws XMLSignerException;
	
	/**
	 * Verify signature from String that represents a XML Document The content must contains both content and signature
	 *
	 * @param xmlAsString fake.
	 * @return fake.
	 * @throws XMLSignerException 
	 */
	public boolean check(String xmlAsString) throws XMLSignerException;

	/**
	 * Get signature informations after validation.
	 * 
	 * @return
	 */
	List<XMLSignatureInformations> getSignaturesInfo();
}
