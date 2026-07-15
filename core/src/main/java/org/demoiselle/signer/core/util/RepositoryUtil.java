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
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

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
	 * Configura SSL para aceitar qualquer certificado (equivalente a curl -k).
	 * Usado apenas para download de CRLs de servidores com certificado inválido/auto-assinado.
	 * 
	 * @param httpsConnection Conexão HTTPS a configurar
	 */
	private static void setupInsecureSSL(HttpsURLConnection httpsConnection) {
		try {
			// Cria TrustManager que aceita todos os certificados
			TrustManager[] trustAllCerts = new TrustManager[] {
				new X509TrustManager() {
					public X509Certificate[] getAcceptedIssuers() {
						return null;
					}
					public void checkClientTrusted(X509Certificate[] certs, String authType) {
					}
					public void checkServerTrusted(X509Certificate[] certs, String authType) {
					}
				}
			};

			// Cria SSLContext com o TrustManager permissivo
			SSLContext sc = SSLContext.getInstance("SSL");
			sc.init(null, trustAllCerts, new java.security.SecureRandom());
			httpsConnection.setSSLSocketFactory(sc.getSocketFactory());

			// Desabilita verificação de hostname
			httpsConnection.setHostnameVerifier(new HostnameVerifier() {
				public boolean verify(String hostname, SSLSession session) {
					return true;
				}
			});
			
			logger.debug("SSL verificacao desabilitada para download de CRL");
		} catch (Exception e) {
			logger.warn("Nao foi possivel desabilitar verificacao SSL: " + e.getMessage());
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
		
		// Estratégia: tentar HTTP primeiro, depois HTTPS sem verificação de certificado
		String primaryUrl = sUrl;
		String fallbackUrl = null;
		
		if (sUrl.startsWith("http://")) {
			// URL é HTTP, tentamos HTTP primeiro
			primaryUrl = sUrl;
			fallbackUrl = sUrl.replace("http://", "https://"); // HTTPS como fallback
			logger.info("Tentando HTTP primeiro (fallback para HTTPS se necessário): " + primaryUrl);
		} else {
			logger.info("URL já é HTTPS: " + sUrl);
		}
		
		try {
			logger.info(coreMessagesBundle.getString("info.file.destination", destinationFile));
			url = new URL(primaryUrl);
			
			ConfigurationRepo conf = ConfigurationRepo.getInstance();
			uCon = url.openConnection(conf.getProxy());
			
			uCon.setConnectTimeout(conf.getCrlTimeOut());
			uCon.setReadTimeout(conf.getCrlTimeOut());
			is = uCon.getInputStream();
				
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
			logger.info("Download bem-sucedido via " + (primaryUrl.startsWith("https://") ? "HTTPS" : "HTTP"));
		} catch (MalformedURLException e) {
			logger.error(coreMessagesBundle.getString("error.malformed.url", primaryUrl));
			throw new CertificateValidatorException(coreMessagesBundle.getString("error.malformed.url", primaryUrl), e);
		} catch (FileNotFoundException e) {
			logger.error(coreMessagesBundle.getString("error.file.not.found", primaryUrl));
			throw new CertificateValidatorException(coreMessagesBundle.getString("error.file.not.found", primaryUrl), e);
		} catch (IOException e) {
			// Se falhou com HTTP e existe fallback HTTPS, tenta com HTTPS sem verificação
			if (fallbackUrl != null) {
				logger.warn("Falha ao baixar via HTTP, tentando HTTPS sem verificacao de certificado: " + e.getMessage());
				try {
					if (is != null) is.close();
					if (outStream != null) outStream.close();
				} catch (Exception ex) {}
				
				// Retry com HTTPS sem verificação
				try {
					url = new URL(fallbackUrl);
					ConfigurationRepo conf = ConfigurationRepo.getInstance();
					uCon = url.openConnection(conf.getProxy());
					
					// Desabilita verificação de certificado para HTTPS
					if (uCon instanceof HttpsURLConnection) {
						setupInsecureSSL((HttpsURLConnection) uCon);
					}
					
					uCon.setConnectTimeout(conf.getCrlTimeOut());
					uCon.setReadTimeout(conf.getCrlTimeOut());
					is = uCon.getInputStream();
					
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
					logger.info("Download bem-sucedido via HTTPS sem verificacao");
					return;
				} catch (Exception ex) {
					logger.error("Falha tambem com HTTPS: " + ex.getMessage());
					throw new CertificateValidatorException("Falha ao baixar de " + sUrl + " e " + fallbackUrl, ex);
				}
			}
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
