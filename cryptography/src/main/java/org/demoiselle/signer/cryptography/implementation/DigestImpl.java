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

package org.demoiselle.signer.cryptography.implementation;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.demoiselle.signer.cryptography.CryptographyException;
import org.demoiselle.signer.cryptography.Digest;
import org.demoiselle.signer.cryptography.DigestAlgorithmEnum;
import org.demoiselle.signer.cryptography.util.MessagesBundle;

/**
 * Implementation of the Digest methods.
 */
public class DigestImpl implements Digest {

	private String algorithm = DigestAlgorithmEnum.DEFAULT.getAlgorithm();
	private final int BUFSIZE = 256;
	private static MessagesBundle crytographyMessagesBundle = new MessagesBundle("messages_cryptography");

	// FIXME should check the name (avoid garbage-in garbage-out)
	@Override
	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}

	/**
	 * Method responsible for generating a summary of bytes passed as parameter.
	 * It uses the SHA256 algorithm as default.
	 */
	@Override
	public byte[] digest(byte[] content) {
		byte[] result = null;

		if (this.algorithm == null)
			this.algorithm = DigestAlgorithmEnum.DEFAULT.getAlgorithm();

		if (content == null)
			throw new CryptographyException(crytographyMessagesBundle.getString("error.content.null"));

		try {
			MessageDigest digest = MessageDigest.getInstance(this.algorithm);
			digest.update(content);
			result = digest.digest();
		} catch (Throwable error) {
			throw new CryptographyException(crytographyMessagesBundle.getString("error.digest.generate"), error);
		}

		return result;
	}

	@Override
	public byte[] digestFile(File file) {
		try {
			MessageDigest md = MessageDigest.getInstance(this.algorithm);
			FileInputStream fileIS = new FileInputStream(file);
			BufferedInputStream bis = new BufferedInputStream(fileIS);
			// FIXME no need for this extra brocker DataInputStream
			DataInputStream dis = new DataInputStream(bis);
			DigestInputStream digin = new DigestInputStream(dis, md);
			byte[] buffer = new byte[BUFSIZE];
			while (digin.read(buffer, 0, BUFSIZE) != -1)
				;
			digin.close();
			return md.digest();
		} catch (NoSuchAlgorithmException e) {
			throw new CryptographyException(crytographyMessagesBundle.getString("error.set.algorithm"), e);
		} catch (FileNotFoundException e) {
			throw new CryptographyException(crytographyMessagesBundle.getString("error.file.not.found", file), e);
		} catch (IOException e) {
			throw new CryptographyException(crytographyMessagesBundle.getString("error.reading.file", file), e);
		}
	}

	@Override
	public String digestFileHex(File file) {
		byte[] bytes = this.digestFile(file);
		String hex = this.convertToHex(bytes);
		return hex;
	}

	@Override
	public String digestHex(byte[] content) {
		byte[] bytes = this.digest(content);
		String hex = this.convertToHex(bytes);
		return hex;
	}

	/**
	 * FIXME goes to core (reused in many places)
	 * convert a byte[] into HEXADECIMAL base content.
	 *
	 * @param data
	 * @return
	 */
	private String convertToHex(byte[] data) {
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < data.length; i++) {
			int halfbyte = (data[i] >>> 4) & 0x0F;
			int two_halfs = 0;
			do {
				if ((0 <= halfbyte) && (halfbyte <= 9))
					buf.append((char) ('0' + halfbyte));
				else
					buf.append((char) ('a' + (halfbyte - 10)));
				halfbyte = data[i] & 0x0F;
			} while (two_halfs++ < 1);
		}
		return buf.toString();

	}

	@Override
	public void setAlgorithm(DigestAlgorithmEnum algorithm) {
		this.setAlgorithm(algorithm.getAlgorithm());
	}

}
