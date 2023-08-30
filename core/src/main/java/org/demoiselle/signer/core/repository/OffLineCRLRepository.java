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

package org.demoiselle.signer.core.repository;

import org.demoiselle.signer.core.exception.CertificateValidatorException;
import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.core.extension.ICPBR_CRL;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.demoiselle.signer.core.util.RepositoryUtil;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of an Offline Repository.
 * In this case, only the file system will be used to recover the CRL files.
 * It is recommended in this case, that there is some service constantly updating these CRL's files.
 */
public class OffLineCRLRepository implements CRLRepository {

	private final ConfigurationRepo config;
	private final Logger logger = LoggerFactory.getLogger(OffLineCRLRepository.class);
	private static MessagesBundle coreMessagesBundle = new MessagesBundle();

	/**
	 * New Instance
	 */
	public OffLineCRLRepository() {
		config = ConfigurationRepo.getInstance();
	}

	/**
	 * Returns a CRL (Certificate Revoked List)  from a given authority of IPC-Brasil.
	 * @throws NoSuchProviderException 
	 */
	@Override
	public Collection<ICPBR_CRL> getX509CRL(X509Certificate certificate) throws NoSuchProviderException {

		Collection<ICPBR_CRL> list = new ArrayList<ICPBR_CRL>();
		try {
			BasicCertificate cert = new BasicCertificate(certificate);
			List<String> ListaURLCRL = cert.getCRLDistributionPoint();

			if (ListaURLCRL == null || ListaURLCRL.isEmpty()) {
				logger.error(coreMessagesBundle.getString("error.invalid.crl"));
				throw new CRLRepositoryException(coreMessagesBundle.getString("error.invalid.crl"));
			}

			ICPBR_CRL validCrl = null;
			for (String URLCRL : ListaURLCRL) {
				// Achou uma CRL válida
				validCrl = getICPBR_CRL(URLCRL);
				if (validCrl != null) {
					list.add(validCrl);
					logger.debug(coreMessagesBundle.getString("info.crl.offline.found"));
					break;
				}
			}
			if (validCrl == null) {
				logger.error(coreMessagesBundle.getString("error.validate.on.crl", ListaURLCRL));
				throw new CRLRepositoryException(coreMessagesBundle.getString("error.validate.on.crl", ListaURLCRL));
			}

		} catch (IOException e) {
			logger.error(coreMessagesBundle.getString("error.invalid.crl") + e.getMessage());
			throw new CRLRepositoryException(coreMessagesBundle.getString("error.invalid.crl") + e.getMessage());
		}
		return list;
	}

	/**
	 * @param uRLCRL a valid url address
	 * @return
	 * @throws NoSuchProviderException 
	 */
	private ICPBR_CRL getICPBR_CRL(String uRLCRL) throws NoSuchProviderException {

		File fileCRL = null;

		try {
			ICPBR_CRL crl = null;

			if (new File(config.getCrlPath()).mkdirs()) {
				logger.debug(coreMessagesBundle.getString("info.creating.crl", config.getCrlPath()));
			} else {
				logger.debug(coreMessagesBundle.getString("info.created.crl", config.getCrlPath()));
			}

			fileCRL = new File(config.getCrlPath(), RepositoryUtil.urlToMD5(uRLCRL));
			if (!fileCRL.exists()) {
				RepositoryUtil.saveURL(uRLCRL, fileCRL);
			}

			if (fileCRL.length() != 0) {
				crl = new ICPBR_CRL(new FileInputStream(fileCRL));
				if (crl.getCRL().getNextUpdate().before(new Date())) {
					// Se estiver expirado, atualiza com a CRL mais nova
					logger.info(coreMessagesBundle.getString("info.update.crl"));
					RepositoryUtil.saveURL(uRLCRL, fileCRL);
				}
			} else {
				if (!fileCRL.delete()) {
					logger.error(coreMessagesBundle.getString("error.file.remove", fileCRL));
					config.setOnline(true);
				}
			}
			return crl;

		} catch (FileNotFoundException e) {
			addFileIndex(uRLCRL);
			logger.error(coreMessagesBundle.getString("error.file.not.found", fileCRL));
			config.setOnline(true);
		} catch (CRLException e) {
			addFileIndex(uRLCRL);
			logger.error(coreMessagesBundle.getString("error.file.corrupted", fileCRL, e.getMessage()));
			config.setOnline(true);
			if (!fileCRL.delete()) {
				logger.error(coreMessagesBundle.getString("error.file.remove", fileCRL));
			}
		} catch (CertificateException e) {
			addFileIndex(uRLCRL);
			config.setOnline(true);
			logger.error(coreMessagesBundle.getString("error.crl.certificate", e.getMessage()));
		}
		return null;
	}

	/**
	 * When the crl file is not in the local repository, it must be registered in the index file.
	 *
	 * @param url CRL url to be registered on the index file
	 */
	public void addFileIndex(String url) {
		String fileNameCRL = RepositoryUtil.urlToMD5(url);
		File fileIndex = new File(config.getCrlPath(), config.getCrlIndex());
		if (!fileIndex.exists()) {
			try {
				File diretory = new File(config.getCrlPath());
				diretory.mkdirs();
				fileIndex.createNewFile();
			} catch (Exception e) {
				logger.error(coreMessagesBundle.getString("error.file.index.create", fileIndex) + e.getMessage());
				throw new CertificateValidatorException(coreMessagesBundle.getString("error.file.index.create", fileIndex), e);
			}
		}
		Properties prop = new Properties();
		try {
			prop.load(new FileInputStream(fileIndex));
		} catch (Exception e) {
			logger.error(coreMessagesBundle.getString("error.file.index.create", fileIndex) + e.getMessage());
			throw new CertificateValidatorException(coreMessagesBundle.getString("error.file.index.create", fileIndex), e);
		}
		prop.put(fileNameCRL, url);
		try {
			prop.store(new FileOutputStream(fileIndex), null);
		} catch (Exception e) {
			logger.error(coreMessagesBundle.getString("error.file.index.create", fileIndex) + e.getMessage());
			throw new CertificateValidatorException(coreMessagesBundle.getString("error.file.index.create", fileIndex), e);
		}
	}
}
