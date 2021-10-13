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

import java.security.cert.X509Certificate;
import java.text.Format;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.demoiselle.signer.core.IValidator;
import org.demoiselle.signer.core.exception.CertificateValidatorException;
import org.demoiselle.signer.core.util.MessagesBundle;

/**
 * check if a Certificate is out of date
 */
public class PeriodValidator implements IValidator {

	private static MessagesBundle coreMessagesBundle = new MessagesBundle();

	@Override
	public void validate(X509Certificate x509) throws CertificateValidatorException {
		try {
			if (x509 != null) {
				x509.checkValidity();
			} else {
				throw new CertificateValidatorException(coreMessagesBundle.getString("error.invalid.certificate"));
			}

		} catch (Exception e) {
			Format formatter = new SimpleDateFormat("dd.MM.yyyy");
			throw new CertificateValidatorException(coreMessagesBundle.getString("error.certificate.out.date",
				formatter.format(x509.getNotBefore()), formatter.format(x509.getNotAfter())), e);
		}
	}

	public Date valDate(X509Certificate x509) throws CertificateValidatorException {
		try {
			if (x509 != null) {
				x509.checkValidity();
			} else {
				throw new CertificateValidatorException(coreMessagesBundle.getString("error.invalid.certificate"));
			}

		} catch (Exception e) {
			Format formatter = new SimpleDateFormat("dd.MM.yyyy");
			throw new CertificateValidatorException(coreMessagesBundle.getString("error.certificate.out.date",
				formatter.format(x509.getNotBefore()), formatter.format(x509.getNotAfter())), e);
		}
		return x509.getNotAfter();
	}

}
