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
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import org.demoiselle.signer.core.exception.CertificateValidatorException;
import org.demoiselle.signer.core.repository.ConfigurationRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utilities related to CRL (Certificate Revocation list).
 */
public class RepositoryUtil {

	private static Logger logger = LoggerFactory.getLogger(RepositoryUtil.class);
	private static MessagesBundle coreMessagesBundle = new MessagesBundle();
	private static int byteWritten;
	private static int byteWritten2;

	/**
	 * Digest to hexadecimal MD5.
	 *
	 * @param url source url
	 * @return MD5 digest
	 */
	public static String urlToMD5(String url) {
		try {
			String ret = "";
			MessageDigest md = MessageDigest.getInstance("MD5");
			md.update(url.getBytes(), 0, url.length());
			for (byte b : md.digest()) ret = ret + String.format("%02x", b);
			return ret;
		} catch (NoSuchAlgorithmException e) {
			logger.error(e.getMessage());
			return null;
		}
	}

	/**
	 * @param sUrl            source url
	 * @param destinationFile destination file
	 */
	@SuppressWarnings("resource")
	public static void saveURL(String sUrl, File destinationFile) {
		URL url;
		byte[] buf;
		int ByteRead;
		setByteWritten(0);
		BufferedOutputStream outStream = null;
		URLConnection uCon = null;
		InputStream is = null;
		try {
			logger.info(coreMessagesBundle.getString("info.file.destination", destinationFile));
			url = new URL(sUrl);
			
			ConfigurationRepo conf = ConfigurationRepo.getInstance();
			uCon = url.openConnection(conf.getProxy());
			uCon.setConnectTimeout(conf.getCrlTimeOut());
			uCon.setReadTimeout(conf.getCrlTimeOut());
			try {
				is = uCon.getInputStream();
			} catch (Exception e) {
				String newUrl = sUrl.replace("http://", "https://");
				logger.info(newUrl);
				url = new URL(newUrl);
				uCon = url.openConnection(conf.getProxy());
				uCon.setConnectTimeout(conf.getCrlTimeOut());
				uCon.setReadTimeout(conf.getCrlTimeOut());
				is = uCon.getInputStream();
			}
				
			outStream = new BufferedOutputStream(new FileOutputStream(destinationFile));
			buf = new byte[1024];
			while ((ByteRead = is.read(buf)) != -1) {
				outStream.write(buf, 0, ByteRead);
				setByteWritten(getByteWritten() + ByteRead);
			}
			outStream.flush();
			if (destinationFile.length() <= 0) {
				if (!destinationFile.delete()) {
					logger.warn(coreMessagesBundle.getString("error.file.remove", destinationFile));
				}
			}
			is.close();
		} catch (MalformedURLException e) {
			logger.error(coreMessagesBundle.getString("error.malformed.url", sUrl));
			throw new CertificateValidatorException(coreMessagesBundle.getString("error.malformed.url", sUrl), e);
		} catch (FileNotFoundException e) {
			logger.error(coreMessagesBundle.getString("error.file.not.found", sUrl));
			throw new CertificateValidatorException(coreMessagesBundle.getString("error.file.not.found", sUrl), e);
		} catch (IOException e) {
			logger.error(coreMessagesBundle.getString("error.io", e.getMessage()));
			throw new CertificateValidatorException(coreMessagesBundle.getString("error.io", e.getMessage()), e);
		} finally {
			try {
				if (is != null) {
					is.close();
				}
				if (outStream != null) {
					outStream.close();
				}
			} catch (Throwable e) {
				logger.error(coreMessagesBundle.getString("error.crl.close.connection", sUrl));
				throw new CertificateValidatorException(coreMessagesBundle.getString("error.crl.close.connection", sUrl), e);
			}
		}
	}

	/**
	 * @param listURL url list
	 * @return valid url list
	 */
	public static List<String> filterValidURLs(List<String> listURL) {
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
		int ByteRead;
		setByteWritten2(0);
		URLConnection uCon = null;
		InputStream is = null;
		try {
			url = new URL(sUrl);
			ConfigurationRepo conf = ConfigurationRepo.getInstance();
			uCon = url.openConnection(conf.getProxy());
			uCon.setConnectTimeout(conf.getCrlTimeOut());
			uCon.setReadTimeout(conf.getCrlTimeOut());
			is = uCon.getInputStream();
			buf = new byte[1024];
			while ((ByteRead = is.read(buf)) != -1) {
				setByteWritten2(getByteWritten2() + ByteRead);
			}
		} catch (MalformedURLException e) {
			logger.error(e.getMessage());
			return false;
		} catch (FileNotFoundException e) {
			logger.error(e.getMessage());
			return false;
		} catch (IOException e) {
			logger.error(e.getMessage());
			return false;
		} finally {
			try {
				if (is != null) {
					is.close();
				}
			} catch (Throwable e) {
				logger.error(coreMessagesBundle.getString("error.crl.close.connection", sUrl) + e.getMessage());
				throw new CertificateValidatorException(coreMessagesBundle.getString("error.crl.close.connection", sUrl), e);
			}
		}

		return true;
	}

	public static int getByteWritten() {
		return byteWritten;
	}

	public static void setByteWritten(int byteWritten) {
		RepositoryUtil.byteWritten = byteWritten;
	}

	public static int getByteWritten2() {
		return byteWritten2;
	}

	public static void setByteWritten2(int byteWritten2) {
		RepositoryUtil.byteWritten2 = byteWritten2;
	}
}
