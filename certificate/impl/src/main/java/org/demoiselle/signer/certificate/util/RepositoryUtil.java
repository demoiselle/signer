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
package org.demoiselle.signer.certificate.util;

import org.demoiselle.signer.certificate.exception.CertificateValidatorException;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RepositoryUtil {

    private static Logger logger = LoggerFactory.getLogger(RepositoryUtil.class);

    public static String urlToMD5(String url) {
        try {
            String ret;
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(url.getBytes());
            BigInteger bigInt = new BigInteger(1, md.digest());
            ret = bigInt.toString(16);
            return ret;
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    public static void saveURL(String sUrl, File destinationFile) {
        URL url;
        byte[] buf;
        int ByteRead, ByteWritten = 0;
        BufferedOutputStream outStream = null;
        URLConnection uCon = null;
        InputStream is = null;
        try {
            url = new URL(sUrl);
            uCon = url.openConnection();
            uCon.setConnectTimeout(5000);
            is = uCon.getInputStream();
            outStream = new BufferedOutputStream(new FileOutputStream(destinationFile));
            buf = new byte[1024];
            while ((ByteRead = is.read(buf)) != -1) {
                outStream.write(buf, 0, ByteRead);
                ByteWritten += ByteRead;
            }
        } catch (MalformedURLException e) {
            throw new CertificateValidatorException("URL [" + sUrl + "] is Malformed", e);
        } catch (FileNotFoundException e) {
            throw new CertificateValidatorException("File [" + sUrl + "] is not found", e);
        } catch (IOException e) {
            logger.info("Error in  url openConnection [" + sUrl + "]" + e.getMessage());
        } finally {
            try {
                if (is != null) {
                    is.close();
                }
                if (outStream != null) {
                    outStream.close();
                }
            } catch (Throwable e) {
                throw new CertificateValidatorException("Is not possible close conection [" + sUrl + "]", e);
            }
        }
    }

    public static List<String> filtervalidURLs(List<String> listURL) {
        List<String> newURLlist = new ArrayList<String>();
        for (String sURL : listURL) {
            if (validateURL(sURL)) {
                newURLlist.add(sURL);
                // break;
            }
        }
        return newURLlist;
    }

    private static boolean validateURL(String sUrl) {
        URL url;
        byte[] buf;
        int ByteRead, ByteWritten = 0;
        URLConnection uCon = null;
        InputStream is = null;
        try {
            url = new URL(sUrl);
            uCon = url.openConnection();
            uCon.setConnectTimeout(5000);
            is = uCon.getInputStream();
            buf = new byte[1024];
            while ((ByteRead = is.read(buf)) != -1) {
                ByteWritten += ByteRead;
            }
        } catch (MalformedURLException e) {
            return false;
        } catch (FileNotFoundException e) {
            return false;
        } catch (IOException e) {
            return false;
        } finally {
            try {
                if (is != null) {
                    is.close();
                }
            } catch (Throwable e) {
                throw new CertificateValidatorException("Is not possible close conection [" + sUrl + "]", e);
            }
        }

        return true;
    }

}
