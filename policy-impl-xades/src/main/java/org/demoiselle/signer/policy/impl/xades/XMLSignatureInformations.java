/*
 * Demoiselle Framework
 * Copyright (C) 2020 SERPRO
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

package org.demoiselle.signer.policy.impl.xades;

import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedList;
import java.util.TimeZone;

import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.policy.engine.xml.icpb.XMLSignaturePolicy;
import org.demoiselle.signer.timestamp.Timestamp;

/**
 * Basic informations about a signature that was validated.
 *
 * @author emerson.saito@gmail.com
 */
public class XMLSignatureInformations {

	private LinkedList<X509Certificate> chain;
	private Date signDate;
	private Timestamp timeStampSigner = null;
	private XMLSignaturePolicy signaturePolicy;
	private Date notAfter;
	private LinkedList<String> validatorWarnins = new LinkedList<String>();
	private LinkedList<String> validatorErrors = new LinkedList<String>();
	private boolean invalidSignature = false;
	private BasicCertificate icpBrasilcertificate = null;

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
	 * @return Date on user's computer when signature was generated (it is NOT a timestamp date)
	 */
	public Date getSignDate() {
		return signDate;
	}

	/**
	 * @return String on user's computer in GMT format (dd-MMM-yyyy HH:mm:ss:S z) when signature was generated (it is NOT a timestamp date)
	 */
	public String getSignDateGMT() {
		if (this.signDate != null) {
			SimpleDateFormat dateFormatGmt = new SimpleDateFormat("dd-MMM-yyyy HH:mm:ss:S z");
			dateFormatGmt.setTimeZone(TimeZone.getTimeZone("GMT"));
			return dateFormatGmt.format(this.getSignDate());
		} else {
			return null;
		}
	}

	/**
	 * Set Date from user's computer when signature was generated (it is NOT a timestamp date)
	 *
	 * @param signDate the date in which signature was generated.
	 */
	public void setSignDate(Date signDate) {
		this.signDate = signDate;
	}

	/**
	 * @return TimeStamp stored on signature
	 */
	public Timestamp getTimeStampSigner() {
		return timeStampSigner;
	}

	/**
	 * TimeStamp stored on signature.
	 *
	 * @param timeStampSigner the timestamp.
	 */
	public void setTimeStampSigner(Timestamp timeStampSigner) {
		this.timeStampSigner = timeStampSigner;
	}


	/**
	 * @return the Signature Policy used
	 */
	public XMLSignaturePolicy getSignaturePolicy() {
		return signaturePolicy;
	}

	/**
	 * @param signaturePolicy the policy.
	 */
	public void setSignaturePolicy(XMLSignaturePolicy signaturePolicy) {
		this.signaturePolicy = signaturePolicy;
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
}
