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

package org.demoiselle.signer.core.util;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * FIXME @Deprecated ?
 * Utility class for compress and decompress data.
 */
public final class ZipBytes {

	private static final Logger LOGGER = LoggerFactory.getLogger(ZipBytes.class.getName());
	private final static int BUFFER_SIZE = 4096;
	private static MessagesBundle coreMessagesBundle = new MessagesBundle();

	/**
	 * @param files files to compress
	 * @return compressed bundle
	 */
	public static byte[] compressing(Map<String, byte[]> files) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ZipOutputStream zipOut = new ZipOutputStream(out);

		try {
			for (String fileName : files.keySet()) {
				LOGGER.info(coreMessagesBundle.getString("info.add.file.zip", fileName));
				zipOut.putNextEntry(new ZipEntry(fileName));
				zipOut.write(files.get(fileName));
				zipOut.setLevel(0);
				zipOut.closeEntry();
			}
			zipOut.close();
			out.close();

		} catch (IOException e) {
			new CertificateUtilException(e.getMessage(), e);
		}

		return out.toByteArray();
	}

	/**
	 * @param file bundle of compressed files
	 * @return uncompressed files, as a map
	 */
	public static Map<String, byte[]> decompressing(byte[] file) {

		BufferedOutputStream dest = null;
		ZipEntry entry = null;

		Map<String, byte[]> files = new HashMap<String, byte[]>();

		InputStream in = new ByteArrayInputStream(file);
		ZipInputStream zipStream = new ZipInputStream(in);

		try {
			while ((entry = zipStream.getNextEntry()) != null) {
				int count;
				byte buf[] = new byte[BUFFER_SIZE];
				ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
				dest = new BufferedOutputStream(outputStream, BUFFER_SIZE);
				while ((count = zipStream.read(buf, 0, BUFFER_SIZE)) != -1) {
					dest.write(buf, 0, count);
				}
				dest.flush();
				dest.close();
				files.put(entry.getName(), outputStream.toByteArray());
				zipStream.closeEntry();
			}
		} catch (IOException e) {
			new CertificateUtilException(e.getMessage(), e);
		}

		return files;
	}
}
