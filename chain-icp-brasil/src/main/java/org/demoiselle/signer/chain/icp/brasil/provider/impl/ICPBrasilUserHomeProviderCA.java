/*
 * Demoiselle Framework
 * Copyright (C) 2010 SERPRO
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

package org.demoiselle.signer.chain.icp.brasil.provider.impl;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.demoiselle.signer.core.ca.provider.ProviderCA;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * FIXME each provider should be independent of any other
 * Get the ICP-BRASIL's Trusted Certificate Authority Chain from file
 * (ACcompactado.zip) stored on user home folder, that was previous
 * downloaded by {@link ICPBrasilOnLineSerproProviderCA} or
 * {@link ICPBrasilOnLineITIProviderCA}.
 */
public class ICPBrasilUserHomeProviderCA implements ProviderCA {

	public static final String PATH_HOME_USER = System.getProperty("user.home");
	public static final String FOLDER_SIGNER = ".java" + File.separator + "signer";
	public static final String FILENAME_ZIP = "ACcompactado.zip";
	public static final String FILENAME_HASH = "hashsha512.txt";

	public static final Path FULL_PATH_FOLDER_SIGNER = Paths.get(PATH_HOME_USER, FOLDER_SIGNER);
	public static final Path FULL_PATH_ZIP = Paths.get(PATH_HOME_USER, FOLDER_SIGNER, FILENAME_ZIP);
	public static final Path FULL_PATH_HASH = Paths.get(PATH_HOME_USER, FOLDER_SIGNER, FILENAME_HASH);

	//private static final Logger LOGGER = Logger.getLogger(ICPBrasilUserHomeProviderCA.class);
	private static final Logger LOGGER = LoggerFactory.getLogger(ICPBrasilUserHomeProviderCA.class);
	
	private static final MessagesBundle chainMessagesBundle = new MessagesBundle();

	/**
	 * Main method for read trusted Certificate Authorities Chain
	 */
	@Override
	public Collection<X509Certificate> getCAs() {

		// verify if the FULL_PATH_FOLDER_SINGER exists
		try {
			LOGGER.debug(chainMessagesBundle.getString("info.ca.home"));
			verifyZIPPath();
		} catch (IOException e) {
			LOGGER.warn(chainMessagesBundle.getString("error.throwable") + e.getMessage());
		}

		return getFromLocalZip(FULL_PATH_ZIP);
	}

	/**
	 * Load file from file system and read Certificate Authorities Chain
	 *
	 * @param fileZip file to read from
	 * @return Collection&lt;X509Certificate&gt;
	 */
	public Collection<X509Certificate> getFromLocalZip(Path fileZip) {

		LOGGER.debug(chainMessagesBundle.getString("info.loading.from.file", fileZip.toString()));

		Collection<X509Certificate> result = new HashSet<>();
		long timeBefore = 0;
		long timeAfter = 0;
		try {
			timeBefore = System.currentTimeMillis();

			if (Files.exists(fileZip)) {

				// get file from filesystem
				InputStream inputStream = new FileInputStream(fileZip.toString());

				// get certificates stored on file
				result = this.getFromZip(inputStream);

			} else {
				LOGGER.warn(chainMessagesBundle.getString("error.filenotfound.userhome", fileZip.toString()));
				throw new Exception(chainMessagesBundle.getString("error.filenotfound.userhome", fileZip.toString()));
			}

			timeAfter = System.currentTimeMillis();
		} catch (Throwable error) {
			timeAfter = System.currentTimeMillis();
			LOGGER.warn(chainMessagesBundle.getString("error.throwable") + error.getMessage());
		} finally {
			LOGGER.debug(chainMessagesBundle.getString("info.time.file.userhome", timeAfter - timeBefore));
		}
		return result;
	}

	/**
	 * Verify if folder exists, otherwise will create it
	 *
	 * @return Path
	 * @throws IOException exception
	 */
	public Path verifyZIPPath() throws IOException {

		Path finalFolder = ICPBrasilUserHomeProviderCA.FULL_PATH_FOLDER_SIGNER;

		if (!Files.isDirectory(finalFolder)) {
			Files.createDirectories(finalFolder);
		}

		return finalFolder;
	}

	/**
	 * get all Certificate Authorities stored on file
	 *
	 * @param zip input stream to read from
	 * @return Collection&lt;X509Certificate&gt;
	 * @throws RuntimeException exception
	 */
	public Collection<X509Certificate> getFromZip(InputStream zip) throws RuntimeException {
		Collection<X509Certificate> result = new HashSet<X509Certificate>();
		InputStream in = new BufferedInputStream(zip);
		ZipInputStream zin = new ZipInputStream(in);
		ZipEntry arquivoInterno = null;
		try {
			while ((arquivoInterno = zin.getNextEntry()) != null) {
				try {
					if (!arquivoInterno.isDirectory()) {
						ByteArrayOutputStream out = new ByteArrayOutputStream();
						byte[] b = new byte[512];
						int len = 0;
						while ((len = zin.read(b)) != -1)
							out.write(b, 0, len);
						ByteArrayInputStream is = new ByteArrayInputStream(out.toByteArray());
						out.close();
						X509Certificate certificate;
						try {
							Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
							certificate = (X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(is);
							is.close();
							result.add(certificate);
						} catch (NoSuchProviderException e) {
							LOGGER.warn(chainMessagesBundle.getString("error.invalid.certificate")+e.getMessage());
						}
						
					}
				} catch (CertificateException error) {
					LOGGER.warn(chainMessagesBundle.getString("error.invalid.certificate")+error.getMessage());
				}
			}
		} catch (IOException error) {
			LOGGER.error(chainMessagesBundle.getString("error.stream")+"\n"+error.getMessage());
			throw new RuntimeException(chainMessagesBundle.getString("error.stream"), error);
		}
		return result;
	}

	/**
	 * This provider Name
	 */
	@Override
	public String getName() {
		return chainMessagesBundle.getString("info.provider.name.userhome", FULL_PATH_ZIP);
	}
}
