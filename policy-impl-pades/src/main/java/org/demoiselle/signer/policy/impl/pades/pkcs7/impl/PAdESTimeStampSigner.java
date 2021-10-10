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

package org.demoiselle.signer.policy.impl.pades.pkcs7.impl;

import java.io.IOException;
import java.security.Security;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.demoiselle.signer.core.exception.CertificateCoreException;
import org.demoiselle.signer.policy.impl.cades.SignerException;
import org.demoiselle.signer.policy.impl.pades.pkcs7.PKCS7TimeStampSigner;
import org.demoiselle.signer.timestamp.Timestamp;
import org.demoiselle.signer.timestamp.connector.TimeStampOperator;

/**
 * Basic implementation of Time Stamp on PADES format.
 */
public class PAdESTimeStampSigner implements PKCS7TimeStampSigner {

	@Override
	public Timestamp checkTimeStampPDFWithContent(byte[] timeStamp, byte[] content) {
		try {
			return this.checkTimeStampPDF(timeStamp, content, null);
		} catch (CertificateCoreException e) {
			throw new SignerException(e);
		}
	}

	@Override
	public Timestamp checkTimeStampPDFWithHash(byte[] timeStamp, byte[] hash) {
		try {
			return this.checkTimeStampPDF(timeStamp, null, hash);
		} catch (CertificateCoreException e) {
			throw new SignerException(e);
		}
	}

	private Timestamp checkTimeStampPDF(byte[] timeStamp, byte[] content, byte[] hash) {
		try {
			Security.addProvider(new BouncyCastleProvider());
			byte[] varTimeStamp = timeStamp;
			TimeStampOperator timeStampOperator = new TimeStampOperator();
			if (content != null) {
				timeStampOperator.validate(content, varTimeStamp, null);
			} else {
				timeStampOperator.validate(null, varTimeStamp, hash);
			}
			TimeStampToken timeStampToken = new TimeStampToken(new CMSSignedData(varTimeStamp));
			Timestamp timeStampSigner = new Timestamp(timeStampToken);
			return timeStampSigner;
		} catch (CertificateCoreException | IOException | TSPException
			| CMSException e) {
			throw new SignerException(e);
		}
	}
}
