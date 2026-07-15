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
package org.demoiselle.signer.core.validator;

import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;

import org.demoiselle.signer.core.IValidator;
import org.demoiselle.signer.core.exception.CertificateRevocationException;
import org.demoiselle.signer.core.exception.CertificateValidatorCRLException;
import org.demoiselle.signer.core.extension.ICPBR_CRL;
import org.demoiselle.signer.core.repository.CRLRepository;
import org.demoiselle.signer.core.repository.CRLRepositoryFactory;
import org.demoiselle.signer.core.util.MessagesBundle;

/**
 * to verify if a certificate is Repealed.
 */
public class CRLValidator implements IValidator {

	private final CRLRepository crlRepository;
	private static MessagesBundle coreMessagesBundle = new MessagesBundle();

	public CRLValidator() {
		crlRepository = CRLRepositoryFactory.factoryCRLRepository();
	}

	@Override
	public void validate(X509Certificate x509) throws CertificateValidatorCRLException, CertificateRevocationException {
		validate(x509, null);
	}

	/**
	 * Valida se o certificado estava revogado em uma data específica.
	 * 
	 * Se validationDate for null, verifica revogação na data atual.
	 * Se validationDate for fornecida (ex: data do timestamp), verifica se o certificado
	 * estava revogado ANTES dessa data.
	 * 
	 * @param x509 Certificado a ser validado
	 * @param validationDate Data de referência para validação (null = data atual)
	 * @throws CertificateValidatorCRLException
	 * @throws CertificateRevocationException
	 */
	public void validate(X509Certificate x509, Date validationDate) throws CertificateValidatorCRLException, CertificateRevocationException {
		if (x509 != null) {
			Collection<ICPBR_CRL> crls = null;
			try {
				crls = crlRepository.getX509CRL(x509);
			} catch (Exception e) {
				throw new CertificateValidatorCRLException(e.getMessage());
			}

			if (crls == null || crls.isEmpty()) {
				throw new CertificateValidatorCRLException(coreMessagesBundle.getString("error.validate.on.crl", "vazio ou nula"));
			}
			
			for (ICPBR_CRL icpbr_crl : crls) {
				// Se validationDate não foi fornecida, usa verificação padrão (data atual)
				if (validationDate == null) {
					if (icpbr_crl.getCRL().isRevoked(x509)) {
						throw new CertificateRevocationException(coreMessagesBundle.getString("error.certificate.repealed"));
					}
				} else {
					// Verifica se estava revogado ANTES da data de validação (timestamp)
					X509CRLEntry revokedCert = icpbr_crl.getCRL().getRevokedCertificate(x509);
					if (revokedCert != null) {
						Date revocationDate = revokedCert.getRevocationDate();
						// Se foi revogado ANTES do timestamp, a assinatura é inválida
						if (revocationDate.before(validationDate)) {
							throw new CertificateRevocationException(
								coreMessagesBundle.getString("error.certificate.repealed") + 
								" (revogado em " + revocationDate + ", validação em " + validationDate + ")"
							);
						}
						// Se foi revogado DEPOIS do timestamp, a assinatura é válida (certificado era válido no momento da assinatura)
					}
				}
			}
		} else {
			throw new CertificateValidatorCRLException(coreMessagesBundle.getString("error.invalid.certificate"));
		}
	}
}
