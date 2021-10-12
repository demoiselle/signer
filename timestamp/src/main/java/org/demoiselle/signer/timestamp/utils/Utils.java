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

package org.demoiselle.signer.timestamp.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.demoiselle.signer.core.exception.CertificateCoreException;

/**
 * Class with utility methods for the time stamp component.
 */
public class Utils {

	/**
	 * Transforms int to Big Endian according to specification RFC 3161.
	 *
	 * @param value the int value.
	 * @return corresponding bytes of int.
	 */
	public static byte[] intToByteArray(int value) {
		byte buffer[] = new byte[4];

		// PROTOCOL RFC 3161 - format big-endian of JVM
		buffer[0] = (byte) (value >> 24 & 0xff);
		buffer[1] = (byte) (value >> 16 & 0xff);
		buffer[2] = (byte) (value >> 8 & 0xff);
		buffer[3] = (byte) (value & 0xff);

		return buffer;
	}

	/**
	 * Loads the contents of a file from the disk
	 *
	 * @param parmFile Filename and path
	 * @return The array of bytes in the file
	 */
	public static byte[] readContent(String parmFile) throws CertificateCoreException {
		try {
			File file = new File(parmFile);
			InputStream is = new FileInputStream(file);
			byte[] result = new byte[(int) file.length()];
			is.read(result);
			is.close();
			return result;
		} catch (FileNotFoundException ex) {
			throw new CertificateCoreException(ex.getMessage(), ex.getCause());
		} catch (IOException ex) {
			throw new CertificateCoreException(ex.getMessage(), ex.getCause());
		}
	}

	/**
	 * Writes a set of bytes to a file on disk
	 *
	 * @param content  Content to be written to disk
	 * @param parmFile Filename and path
	 * @throws CertificateCoreException fake.
	 */
	public static void writeContent(byte[] content, String parmFile) throws CertificateCoreException {
		try {
			File file = new File(parmFile);
			OutputStream os = new FileOutputStream(file);
			os.write(content);
			os.flush();
			os.close();
		} catch (IOException ex) {
			throw new CertificateCoreException(ex.getMessage(), ex.getCause());
		}
	}
}
