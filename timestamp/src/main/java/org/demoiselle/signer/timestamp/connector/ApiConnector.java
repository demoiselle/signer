/*
 * Demoiselle Framework
 * Copyright (C) 2024 SERPRO
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

package org.demoiselle.signer.timestamp.connector;

import java.io.IOException;
import java.io.InputStream;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.apache.http.HttpResponse;
import org.apache.http.ParseException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.encoders.Base64;
import org.demoiselle.signer.core.exception.CertificateCoreException;
import org.demoiselle.signer.core.keystore.loader.configuration.Configuration;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.demoiselle.signer.timestamp.Timestamp;
import org.demoiselle.signer.timestamp.configuration.TimeStampConfig;
import org.demoiselle.signer.timestamp.utils.TimeStampConfigUtil;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mashape.unirest.http.Unirest;

/**
 * Connects to the timestamp server using the API provided by SERPRO.
 * https://doc-apitimestamp.estaleiro.serpro.gov.br/quick_start/#como-autenticar-na-api-carimbo-do-tempo
 * 
 * @author Emerson Sachio Saito emerson.saito@gmail.com
 */

public class ApiConnector implements Connector {

	private static final Logger logger = LoggerFactory.getLogger(ApiConnector.class);
	private static MessagesBundle timeStampMessagesBundle = new MessagesBundle();
	private String clientCredentials = "";
	private String accessToken = "";
	private TimeStampConfig timeStampConfig = TimeStampConfig.getInstance();
	private TimeStampConfigUtil tscu = TimeStampConfigUtil.getInstance();

	public ApiConnector() throws CertificateCoreException {
		System.setProperty("https.protocols", "TLSv1.2, TLSv1.1");
		System.setProperty("jdk.tls.client.protocols", "TLSv1.2,TLSv1.1");
		this.clientCredentials = timeStampConfig.getClientCredentials();
		this.accessToken = authenticate();
	}

	public ApiConnector(String clientCredentials) throws CertificateCoreException {
		System.setProperty("https.protocols", "TLSv1.2,TLSv1.1");
		System.setProperty("jdk.tls.client.protocols", "TLSv1.2,TLSv1.1");
		this.clientCredentials = clientCredentials;
		this.accessToken = authenticate();

	}

	/**
	 * Authenticate on API
	 * 
	 * @return String with token
	 * @throws CertificateCoreException
	 */
	private String authenticate() throws CertificateCoreException {

		try {
			if (System.getProperty("java.version").contains("1.7")) {				
				Unirest.setHttpClient(getHttpClient());				
			} else {
				Unirest.setTimeouts(timeStampConfig.getTimeOut(), timeStampConfig.getReadTimeOut());
			}
			logger.info(timeStampMessagesBundle.getString("info.timestamp.api.authenticate:", tscu.getApiAuthUrl()));

			com.mashape.unirest.http.HttpResponse<String> response = Unirest.post(tscu.getApiAuthUrl())
					.header("Authorization", "Basic " + getClientCredentials())
					.header("Content-Type", "application/x-www-form-urlencoded")
					.field("grant_type", "client_credentials").asString();

			if (response.getStatus() == 200) {
				String responseBody = response.getBody();
				String varToken = extractAccessToken(responseBody);
				setAccessToken(varToken);
				return this.accessToken;
			} else {
				logger.error(
						timeStampMessagesBundle.getString("error.timestamp.api.authenticate", response.getStatus()));
				throw new CertificateCoreException(
						timeStampMessagesBundle.getString("error.timestamp.api.authenticate", response.getStatus()));
			}
		} catch (Exception e) {
			try {
				Unirest.shutdown();
			} catch (IOException e1) {
				e1.printStackTrace();
			}
			logger.error(timeStampMessagesBundle.getString("error.timestamp.api.authenticate", e.getMessage()));
			throw new CertificateCoreException(
					timeStampMessagesBundle.getString("error.timestamp.api.authenticate", e.getMessage()), e);
		}
	}

	/**
	 * to Extract Acesss Token from response
	 * 
	 * @param responseBody from authenticate()
	 * @return String with token
	 */
	private String extractAccessToken(String responseBody) {
		try {
			ObjectMapper objectMapper = new ObjectMapper();
			JsonNode jsonNode = objectMapper.readTree(responseBody);
			return jsonNode.get("access_token").asText(); // Retorna o valor de access_token
		} catch (Exception e) {
			logger.error(timeStampMessagesBundle.getString("error.timestamp.api.token.extract", e.getMessage()));
			throw new CertificateCoreException(
					timeStampMessagesBundle.getString("error.timestamp.api.token.extract", e.getMessage()), e);
		}
	}

	/**
	 * generates a timestamp from a string given in the parameter.
	 * 
	 * @param parmString a String
	 * @return a base64 string with the timestamp byte array {"stamp": "string"}
	 * @throws CertificateCoreException on error
	 */
	public String getStampBase64(String parmString) throws CertificateCoreException {
		try {
			MessageDigest md = getMessageDigest();
			byte[] hash = md.digest(parmString.getBytes(StandardCharsets.UTF_8));
			String base64Hash = Base64.toBase64String(hash);
			String jsonBody = "{\"hash\": \"" + base64Hash + "\"}";
			StringEntity entity = new StringEntity(jsonBody, "UTF-8");

			HttpPost request = geHttpPost("/stamps");
			request.setEntity(entity);

			HttpClient httpClient;
			if (System.getProperty("java.version").contains("1.7")) {				
				httpClient = getHttpClient();				
			} else {
				httpClient = HttpClients.createDefault();
			}
			
			HttpResponse response = httpClient.execute(request);

			int statusCode = response.getStatusLine().getStatusCode();

			if (statusCode == 200) {
				return EntityUtils.toString(response.getEntity());
			} else {
				logger.error(timeStampMessagesBundle.getString("error.timestamp.api.request", statusCode));
				throw new CertificateCoreException(
						timeStampMessagesBundle.getString("error.timestamp.api.request", statusCode));
			}
		} catch (Exception e) {
			logger.error(timeStampMessagesBundle.getString("error.timestamp.api.connection"), e.getMessage());
			throw new CertificateCoreException(
					timeStampMessagesBundle.getString("error.timestamp.api.connection", e.getMessage()), e);
		}
	}

	/**
	 * generates a timestamp from a string given in the parameter.
	 * 
	 * @param parmString a String
	 * @return {"timestamp": "string","policy": "string","serialNumber":
	 *         "string","timestampAuthorityInfo": "string", "hashAlgorithm":
	 *         "string","hash": "string","stamp": "string"}
	 * @throws CertificateCoreException on error
	 */
	public String getDecodedStamps(String parmString) throws CertificateCoreException {
		try {
			MessageDigest md = getMessageDigest();
			byte[] hash = md.digest(parmString.getBytes(StandardCharsets.UTF_8));
			String base64Hash = Base64.toBase64String(hash);
			String jsonBody = "{\"hash\": \"" + base64Hash + "\"}";
			StringEntity entity = new StringEntity(jsonBody, "UTF-8");

			HttpPost request = geHttpPost("/decoded-stamps");
			request.setEntity(entity);
			
			HttpClient httpClient;
			if (System.getProperty("java.version").contains("1.7")) {				
				httpClient = getHttpClient();				
			} else {
				httpClient = HttpClients.createDefault();
			}

			HttpResponse response = httpClient.execute(request);

			int statusCode = response.getStatusLine().getStatusCode();

			if (statusCode == 200) {
				return EntityUtils.toString(response.getEntity());
			} else {
				logger.error(timeStampMessagesBundle.getString("error.timestamp.api.request", statusCode));
				throw new CertificateCoreException(
						timeStampMessagesBundle.getString("error.timestamp.api.request", statusCode));
			}
		} catch (Exception e) {
			logger.error(timeStampMessagesBundle.getString("error.timestamp.api.connection"), e.getMessage());
			throw new CertificateCoreException(
					timeStampMessagesBundle.getString("error.timestamp.api.connection", e.getMessage()), e);
		}
	}

	/**
	 * generates a timeStamp from a content (byte array)
	 * 
	 * @param content byte[] from a content
	 * @return byte[] with a timeStamp
	 * @throws CertificateCoreException on error
	 */
	public byte[] getStampForContent(byte[] content) throws CertificateCoreException {
		try {
			MessageDigest md = getMessageDigest();
			byte[] hash = md.digest(content);
			String base64Hash = Base64.toBase64String(hash);
			String jsonBody = "{\"hash\": \"" + base64Hash + "\"}";
			StringEntity entity = new StringEntity(jsonBody, "UTF-8");

			HttpPost request = geHttpPost("/stamps");
			request.setEntity(entity);

			HttpClient httpClient;
			if (System.getProperty("java.version").contains("1.7")) {				
				httpClient = getHttpClient();				
			} else {
				httpClient = HttpClients.createDefault();
			}
			HttpResponse response = httpClient.execute(request);

			int statusCode = response.getStatusLine().getStatusCode();

			if (statusCode == 200) {
				Timestamp tsp = getTimestamp(response);
				return tsp.getEncoded();
			} else {
				logger.error(timeStampMessagesBundle.getString("error.timestamp.api.request", statusCode));
				throw new CertificateCoreException(
						timeStampMessagesBundle.getString("error.timestamp.api.request", statusCode));
			}
		} catch (Exception e) {
			logger.error(timeStampMessagesBundle.getString("error.timestamp.api.connection"), e.getMessage());
			throw new CertificateCoreException(
					timeStampMessagesBundle.getString("error.timestamp.api.connection", e.getMessage()), e);
		}
	}

	/**
	 * generates a timestamp from a previously calculated hash
	 * 
	 * @param hash byte[] calculated hash
	 * @return byte[] with a timeStamp
	 * @throws CertificateCoreException on error
	 */
	public byte[] getStampForHash(byte[] hash) throws CertificateCoreException {
		try {
			String base64Hash = Base64.toBase64String(hash);
			String jsonBody = "{\"hash\": \"" + base64Hash + "\"}";
			StringEntity entity = new StringEntity(jsonBody, "UTF-8");

			HttpPost request = geHttpPost("/stamps");
			request.setEntity(entity);

			HttpClient httpClient;
			if (System.getProperty("java.version").contains("1.7")) {				
				httpClient = getHttpClient();				
			} else {
				httpClient = HttpClients.createDefault();
			}
			HttpResponse response = httpClient.execute(request);
			int statusCode = response.getStatusLine().getStatusCode();
			if (statusCode == 200) {
				Timestamp tsp = getTimestamp(response);
				return tsp.getEncoded();
			} else {
				logger.error(timeStampMessagesBundle.getString("error.timestamp.api.request", statusCode));
				throw new CertificateCoreException(
						timeStampMessagesBundle.getString("error.timestamp.api.request", statusCode));
			}
		} catch (Exception e) {
			logger.error(timeStampMessagesBundle.getString("error.timestamp.api.connection"), e.getMessage());
			throw new CertificateCoreException(
					timeStampMessagesBundle.getString("error.timestamp.api.connection", e.getMessage()), e);
		}
	}

	public String getAccessToken() {
		return accessToken;
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

	public String getClientCredentials() {
		return clientCredentials;
	}

	public void setClientCredentials(String clientCredentials) {
		this.clientCredentials = clientCredentials;
	}

	@Override
	public void close() {
		// UNUSED
	}

	@Override
	public void setHostname(String hostname) {
		// UNUSED
	}

	@Override
	public void setPort(int port) {
		// UNUSED
	}

	@Override
	public InputStream connect(byte[] content) throws UnknownHostException, CertificateCoreException {
		// UNUSED
		return null;
	}

	private HttpPost geHttpPost(String pathEndPoint) {
		String varEndPoint = TimeStampConfigUtil.getInstance().getApiEndpointUrl() + pathEndPoint;
		HttpPost request = new HttpPost(varEndPoint);
		request.setHeader("Authorization", "Bearer " + accessToken);
		request.setHeader("Content-Type", "application/json");
		request.setHeader("accept", "application/json");
		return request;
	}

	private Timestamp getTimestamp(HttpResponse response) throws ParseException, IOException, TSPException {
		String jsonResp = EntityUtils.toString(response.getEntity());
		JSONObject jsonObject = new JSONObject(jsonResp);
		String timeStampbase64 = jsonObject.getString("stamp");
		TimeStampResponse timeStampResponse = new TimeStampResponse(Base64.decode(timeStampbase64));
		TimeStampToken timeStampToken = timeStampResponse.getTimeStampToken();
		Timestamp tsp = new Timestamp(timeStampToken);
		return tsp;
	}

	private MessageDigest getMessageDigest() throws NoSuchAlgorithmException {
		MessageDigest md;
		if (Configuration.getInstance().getSO().toLowerCase().indexOf("indows") > 0) {
			logger.debug(timeStampMessagesBundle.getString("info.timestamp.winhash"));
			md = MessageDigest.getInstance("SHA-256");
		} else {
			logger.debug(timeStampMessagesBundle.getString("info.timestamp.linuxhash"));
			md = MessageDigest.getInstance("SHA-512");
		}
		return md;
	}

	private CloseableHttpClient getHttpClient() throws Exception {
		//System.setProperty("javax.net.debug", "all");
		System.setProperty("https.protocols", "TLSv1.2,TLSv1.1");
		System.setProperty("jdk.tls.client.protocols", "TLSv1.2,TLSv1.1");
		TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
			public java.security.cert.X509Certificate[] getAcceptedIssuers() {
				return null;
			}

			public void checkClientTrusted(X509Certificate[] certs, String authType) {
			}

			public void checkServerTrusted(X509Certificate[] certs, String authType) {
			}

		} };

		SSLContext sslcontext = SSLContext.getInstance("SSL");
		sslcontext.init(null, trustAllCerts, new java.security.SecureRandom());
		HttpsURLConnection.setDefaultSSLSocketFactory(sslcontext.getSocketFactory());
		SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext,
	            new String[]{"TLSv1.2"}, null,
	            SSLConnectionSocketFactory.getDefaultHostnameVerifier());
		CloseableHttpClient httpclient = HttpClients.custom().setSSLSocketFactory(sslsf).build();
		return httpclient;		
	}
}
