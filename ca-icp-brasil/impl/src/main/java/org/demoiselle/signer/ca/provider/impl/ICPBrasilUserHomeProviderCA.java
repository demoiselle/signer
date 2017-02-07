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

package org.demoiselle.signer.ca.provider.impl;

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
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.demoiselle.signer.signature.core.ca.provider.ProviderCA;

/**
 * Get the ICP-BRASIL's Trusted Certificate Authority Chain from file (ACcompactado.zip) stored on user home folder,
 * that was previous downloaded by ICPBrasilOnLineSerproProviderCA or ICPBrasilOnLineITIProviderCA.  
 *  *
 */

public class ICPBrasilUserHomeProviderCA implements ProviderCA {

	public static final String PATH_HOME_USER = System.getProperty("user.home");
	public static final String FOLDER_ASSINADOR = ".java" + File.separator + "assinador";
	public static final String FILENAME_ZIP = "ACcompactado.zip";
	public static final String FILENAME_HASH = "hashsha512.txt";

	public static final Path FULL_PATH_FOLDER_ASSINADOR = Paths.get(PATH_HOME_USER, FOLDER_ASSINADOR);
	public static final Path FULL_PATH_ZIP = Paths.get(PATH_HOME_USER, FOLDER_ASSINADOR, FILENAME_ZIP);
	public static final Path FULL_PATH_HASH = Paths.get(PATH_HOME_USER, FOLDER_ASSINADOR, FILENAME_HASH);

	private static final Logger LOGGER = Logger.getLogger(ICPBrasilUserHomeProviderCA.class.getName());

	@Override
	public Collection<X509Certificate> getCAs() {

		// Verifica se a pasta do assinador existe
		try {
			verifyZIPPath();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return getFromLocalZip(FULL_PATH_ZIP);
	}

	public Collection<X509Certificate> getFromLocalZip(Path fileZip) {

		LOGGER.log(Level.INFO, "Recuperando localmente as cadeias da ICP-Brasil [" + fileZip.toString() + "].");

		Collection<X509Certificate> result = new HashSet<X509Certificate>();
		long timeBefore = 0;
		long timeAfter = 0;
		try {
			timeBefore = System.currentTimeMillis();

			if (Files.exists(fileZip)) {

				// Pega o ZIP do filesystem
				InputStream inputStream = new FileInputStream(fileZip.toString());

				// Pega os certificados do ZIP
				result = this.getFromZip(inputStream);

			} else {
				throw new Exception("Arquivo ZIP não encontrado no home do usuário");
			}

			timeAfter = System.currentTimeMillis();
		} catch (Throwable error) {
			timeAfter = System.currentTimeMillis();
			LOGGER.log(Level.WARNING, "ERRO. [" + error.getMessage() + "].");
		} finally {
			LOGGER.log(Level.INFO,
					"Levamos " + (timeAfter - timeBefore) + "ms para tentar recuperar as cadeias do ZIP local.");
		}
		return result;
	}

	public Path verifyZIPPath() throws IOException {

		Path finalFolder = ICPBrasilUserHomeProviderCA.FULL_PATH_FOLDER_ASSINADOR;

		// Verifica se existe o folder, se não cria
		if (!Files.isDirectory(finalFolder)) {
			Files.createDirectories(finalFolder);
		}

		return finalFolder;

	}

	public Collection<X509Certificate> getFromZip(InputStream zip) throws RuntimeException {
		Collection<X509Certificate> result = new HashSet<X509Certificate>();
		InputStream in = new BufferedInputStream(zip);
		ZipInputStream zin = new ZipInputStream(in);
		ZipEntry arquivoInterno = null;
		try {
			while ((arquivoInterno = zin.getNextEntry()) != null) {
				if (!arquivoInterno.isDirectory()) {
					ByteArrayOutputStream out = new ByteArrayOutputStream();
					byte[] b = new byte[512];
					int len = 0;
					while ((len = zin.read(b)) != -1)
						out.write(b, 0, len);
					ByteArrayInputStream is = new ByteArrayInputStream(out.toByteArray());
					out.close();
					X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X509")
							.generateCertificate(is);
					is.close();
					result.add(certificate);
				}
			}
		} catch (CertificateException error) {
			throw new RuntimeException("Certificado inválido", error);
		} catch (IOException error) {
			throw new RuntimeException("Erro ao tentar abrir o stream", error);
		}
		return result;
	}

	@Override
	public String getName() {
		return "Home User Provider";
	}
}
