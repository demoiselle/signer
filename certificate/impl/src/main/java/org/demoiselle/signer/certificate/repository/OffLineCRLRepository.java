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
package org.demoiselle.signer.certificate.repository;

import org.demoiselle.signer.certificate.exception.CertificateValidatorException;
import org.demoiselle.signer.certificate.extension.BasicCertificate;
import org.demoiselle.signer.certificate.extension.ICPBR_CRL;
import org.demoiselle.signer.certificate.util.RepositoryUtil;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
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
 * Implementação de um repositorio Offline. Neste caso apenas o file system será
 * utilizado para recuperar as arquivos CRL. Recomenda-se neste caso de haja
 * algum serviço atualizando constantemente estas CRLs
 */
public class OffLineCRLRepository implements CRLRepository {

    private final Configuration config;
    private final Logger logger = LoggerFactory.getLogger(OffLineCRLRepository.class);

    public OffLineCRLRepository() {
        config = Configuration.getInstance();
    }

    @Override
    public Collection<ICPBR_CRL> getX509CRL(X509Certificate certificate) {

        Collection<ICPBR_CRL> list = new ArrayList<ICPBR_CRL>();
        try {
            BasicCertificate cert = new BasicCertificate(certificate);
            List<String> ListaURLCRL = cert.getCRLDistributionPoint();

            if (ListaURLCRL == null || ListaURLCRL.isEmpty()) {
                throw new CRLRepositoryException("Could not get a valid CRL from Certificate");
            }

            for (String URLCRL : ListaURLCRL) {
                // Achou uma CRL válida
                ICPBR_CRL crl = getICPBR_CRL(URLCRL);
                if (crl != null) {
                    list.add(crl);
                    logger.info("A valid Crl was found. It's not necessary to continue. CRL=[" + URLCRL + "]");
                    break;
                }
            }

        } catch (IOException e) {
            throw new CRLRepositoryException("Could not get the CRL List from Certificate " + e);
        }
        return list;
    }

    private ICPBR_CRL getICPBR_CRL(String uRLCRL) {

        File fileCRL = null;

        try {
            ICPBR_CRL crl = null;

            if (new File(config.getCrlPath()).mkdirs()) {
                logger.info("Creating repository of CRLs.");
            } else {
                logger.info("CRL repository already created.");
            }

            fileCRL = new File(config.getCrlPath(), RepositoryUtil.urlToMD5(uRLCRL));
            if (!fileCRL.exists()) {
                RepositoryUtil.saveURL(uRLCRL, fileCRL);
            }

            if (fileCRL.length() != 0) {
                crl = new ICPBR_CRL(new FileInputStream(fileCRL));
                if (crl.getCRL().getNextUpdate().before(new Date())) {
                    // Se estiver expirado, atualiza com a CRL mais nova
                    logger.info("CRL is old, performing update.");
                    RepositoryUtil.saveURL(uRLCRL, fileCRL);
                }
            }
            return crl;

        } catch (FileNotFoundException e) {
            addFileIndex(uRLCRL);
            logger.info("File [" + fileCRL + "] is not found.");
        } catch (CRLException e) {
            addFileIndex(uRLCRL);
            logger.info("File [" + fileCRL + "] is corrupted, probably due to " + e.getMessage() + ".Removing the corrupted file.");
            if (!fileCRL.delete()) {
                logger.info("There was a failed attempt to file removal.");
            }
        } catch (CertificateException e) {
            addFileIndex(uRLCRL);
            logger.info("Certificate processing failed, caused by " + e.getMessage() + ".");
        }
        return null;
    }

    /**
     * Quando o arquivo crl não se encontra no repositorio local, deve-se
     * cadastra-lo no arquivo de indice.
     *
     * @param url A url a ser cadastrada
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
                throw new CertificateValidatorException("Error creating index file " + fileIndex, e);
            }
        }
        Properties prop = new Properties();
        try {
            prop.load(new FileInputStream(fileIndex));
        } catch (Exception e) {
            throw new CertificateValidatorException("Error on load index file " + fileIndex, e);
        }
        prop.put(fileNameCRL, url);
        try {
            prop.store(new FileOutputStream(fileIndex), null);
        } catch (Exception e) {
            throw new CertificateValidatorException("Error on load index file " + fileIndex, e);
        }
    }
}
