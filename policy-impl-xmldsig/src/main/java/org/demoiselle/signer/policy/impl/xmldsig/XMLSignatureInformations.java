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

package org.demoiselle.signer.policy.impl.xmldsig;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.LinkedList;

import org.demoiselle.signer.core.extension.BasicCertificate;

/**
 * Basic informations about a signature that was validated.
 *
 * @author Eduardo &lt;edumg80@gmail.com&gt;
 */
public class XMLSignatureInformations {

	private BasicCertificate icpBrasilcertificate = null;
	private Date notAfter;
	private LinkedList<X509Certificate> chain = new LinkedList<X509Certificate>();
	private LinkedList<String> validatorWarnins = new LinkedList<String>();
	private LinkedList<String> validatorErrors = new LinkedList<String>();
	private boolean invalidSignature = false;
	private String referenceId = null;

	/**
	 * @return list of Certificate chain stored on signature
	 */
	public LinkedList<X509Certificate> getChain() {
		return chain;
	}

	public void setChain(LinkedList<X509Certificate> chain) {
		this.chain = chain;
	}

	/**
	 * @return a list of Validator Errors
	 */
	public LinkedList<String> getValidatorErrors() {
		return validatorErrors;
	}

	/**
	 * @param validatorErrors the erros produced by validators.
	 */
	public void setValidatorErrors(LinkedList<String> validatorErrors) {
		this.validatorErrors = validatorErrors;
	}

	/**
	 * @return the notAfter certificate date
	 */
	public Date getNotAfter() {
		return notAfter;
	}

	/**
	 * @param notAfter the notAfter to set
	 */
	public void setNotAfter(Date notAfter) {
		this.notAfter = notAfter;
	}

	/**
	 * @return if signature is invalid
	 */
	public boolean isInvalidSignature() {
		return invalidSignature;
	}

	/**
	 * set true (invalid) ou false (valid).
	 *
	 * @param invalidSignature the value signature validity.
	 */
	public void setInvalidSignature(boolean invalidSignature) {
		this.invalidSignature = invalidSignature;
	}

	public BasicCertificate getIcpBrasilcertificate() {
		return icpBrasilcertificate;
	}

	public void setIcpBrasilcertificate(BasicCertificate icpBrasilcertificate) {
		this.icpBrasilcertificate = icpBrasilcertificate;
	}

	public LinkedList<String> getValidatorWarnins() {
		return validatorWarnins;
	}

	public void setValidatorWarnins(LinkedList<String> validatorWarnins) {
		this.validatorWarnins = validatorWarnins;
	}

	public String getReferenceId() {
		return referenceId;
	}

	public void setReferenceId(String referenceId) {
		this.referenceId = referenceId;
	}

}
