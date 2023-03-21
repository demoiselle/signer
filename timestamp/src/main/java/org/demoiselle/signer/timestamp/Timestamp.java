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

package org.demoiselle.signer.timestamp;

import java.io.IOException;
import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.Map;
import java.util.TimeZone;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.demoiselle.signer.core.util.MessagesBundle;

/**
 * It is defined as a ContentInfo([CMS]) and SHALL encapsulate
 * a signed data content type.
 *
 * <pre>
 *     TimeStampToken ::= ContentInfo
 *     -- contentType is id-signedData ([CMS])
 *     -- content is SignedData ([CMS])
 * </pre>
 * id-aa-timeStampToken OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 * us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) aa(2) 14 }
 *
 * @author 07721825741
 */
public class Timestamp {

	private final static Logger logger = LoggerFactory.getLogger(Timestamp.class.getName());
	private static MessagesBundle timeStampMessagesBundle = new MessagesBundle();

	private TimeStampToken timeStampToken = null;

	public Timestamp(TimeStampToken timeStampToken) {
		this.timeStampToken = timeStampToken;
	}

	/**
	 * Returns a stream of bytes encoded in ASN.1 format, which represents the encoded object.
	 *
	 * @return timestamp encoded as a byte[]
	 */
	public byte[] getEncoded() {
		try {
			return timeStampToken.getEncoded();
		} catch (IOException ex) {
			logger.error(ex.getMessage());
		}
		return null;
	}

	public String getPolicy() {
		return timeStampToken.getTimeStampInfo().getPolicy().toString();
	}

	public String getSerialNumber() {
		return timeStampToken.getTimeStampInfo().getSerialNumber().toString();
	}

	public String getHashAlgorithm() {
		return timeStampToken.getTimeStampInfo().getHashAlgorithm().getAlgorithm().toString();
	}

	public byte[] getMessageImprintDigest() {
		return timeStampToken.getTimeStampInfo().getMessageImprintDigest();
	}

	public String getMessageImprintDigestBase64() {
		return Base64.toBase64String(timeStampToken.getTimeStampInfo().getMessageImprintDigest());
	}

	public String getMessageImprintDigestHex() {
		return Hex.toHexString(timeStampToken.getTimeStampInfo().getMessageImprintDigest()).toUpperCase();
	}

	public Store<?> getCRLs() {
		return timeStampToken.getCRLs();
	}

	public Store<?> getCertificates() {
		return timeStampToken.getCertificates();
	}

	public Map<?, ?> getSignedAttributes() {
		return timeStampToken.getSignedAttributes().toHashtable();
	}

	public Map<?, ?> getUnsignedAttributes() {
		return timeStampToken.getUnsignedAttributes().toHashtable();
	}

	/**
	 * The attributes of the Time Stamp Authority's certificate.
	 *
	 * @return Authority information
	 */
	public String getTimeStampAuthorityInfo() {
		return timeStampToken.getTimeStampInfo().getTsa().toString();
	}

	/**
	 * Returns the nonce value, or returns null if there is no
	 *
	 * @return nonce value, or returns null if there is no
	 */
	public BigInteger getNonce() {
		return timeStampToken.getTimeStampInfo().getNonce();
	}

	public String getTimeStamp() {
		SimpleDateFormat dateFormatGmt = new SimpleDateFormat("dd-MMM-yyyy HH:mm:ss:S z");
		dateFormatGmt.setTimeZone(TimeZone.getTimeZone("GMT"));
		return dateFormatGmt.format(timeStampToken.getTimeStampInfo().getGenTime());
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder(0);
		builder.append("\n");
		builder.append(timeStampMessagesBundle.getString("text.timestamp.datetime")).append(this.getTimeStamp()).append("\n");
		builder.append(timeStampMessagesBundle.getString("text.timestamp.policy")).append(this.getPolicy()).append("\n");
		builder.append(timeStampMessagesBundle.getString("text.timestamp.serial.number")).append(this.getSerialNumber()).append("\n");
		builder.append(timeStampMessagesBundle.getString("text.timestamp.certificate")).append(this.getTimeStampAuthorityInfo()).append("\n");
		builder.append(timeStampMessagesBundle.getString("text.timestamp.hash")).append(this.getHashAlgorithm()).append("\n");
		builder.append(timeStampMessagesBundle.getString("text.timestamp.mid.hex")).append(this.getMessageImprintDigestHex()).append("\n");
		builder.append(timeStampMessagesBundle.getString("text.timestamp.mid.base64")).append(this.getMessageImprintDigestBase64()).append("\n");
		builder.append(timeStampMessagesBundle.getString("text.timestamp.mid")).append(this.getMessageImprintDigest()).append("\n");
		return builder.toString();
	}
}
