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

import java.io.InputStream;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.demoiselle.signer.core.exception.CertificateCoreException;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.demoiselle.signer.timestamp.configuration.TimeStampConfig;
import org.demoiselle.signer.timestamp.utils.TimeStampConfigUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
/**
 * Connects to the timestamp server using the API provided by SERPRO.
 * https://doc-apitimestamp.estaleiro.serpro.gov.br/quick_start/#como-autenticar-na-api-carimbo-do-tempo
 * 
 * @author Emerson Sachio Saito<emerson.saito@gmail.com
 */


public class ApiConnector implements Connector {

    private static final Logger logger = LoggerFactory.getLogger(ApiConnector.class);
    private static MessagesBundle timeStampMessagesBundle = new MessagesBundle();
    private String clientCredentials="";
    private String accessToken="06aef429-a981-3ec5-a1f8-71d38d86481e";
    private TimeStampConfig timeStampConfig = TimeStampConfig.getInstance();
    private TimeStampConfigUtil tscu = TimeStampConfigUtil.getInstance();

    public ApiConnector() throws CertificateCoreException {
    	this.clientCredentials = timeStampConfig.getClientCredentials();
        this.accessToken = authenticate();
    }
    
    public ApiConnector(String clientCredentials) throws CertificateCoreException {
    	this.clientCredentials = clientCredentials;
        this.accessToken = authenticate();
    }

    /**
     * Authenticate
     * @return
     * @throws CertificateCoreException
     */
    private String authenticate() throws CertificateCoreException {
    	
        try {
        	logger.info(timeStampMessagesBundle.getString("info.timestamp.api.authenticate:",tscu.getApiAuthUrl()));
        	Unirest.config()
            .socketTimeout(timeStampConfig.getReadTimeOut())
            .connectTimeout(timeStampConfig.getTimeOut());
            HttpResponse<String> response = Unirest.post(tscu.getApiAuthUrl())
            	    .header("Authorization", "Basic "+getClientCredentials())
            	    .header("Content-Type", "application/x-www-form-urlencoded")
            	    .field("grant_type", "client_credentials")
            	    .asString();


            if (response.getStatus() == 200) {
                String responseBody = response.getBody();
                return extractAccessToken(responseBody);
            } else {
            	logger.error(timeStampMessagesBundle.getString("error.timestamp.api.authenticate",response.getStatus()));
            	return this.accessToken;
                //throw new CertificateCoreException(timeStampMessagesBundle.getString("error.timestamp.api.authenticate",response.getStatus()));
            }
        } catch (Exception e) {
        	logger.error("Erro durante a autenticação: " + e.getMessage());
        	return this.accessToken;
            //throw new CertificateCoreException("Erro durante a autenticação: " + e.getMessage(), e);
        }
    }

    String extractAccessToken(String responseBody) {
    	try {
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode jsonNode = objectMapper.readTree(responseBody);
            return jsonNode.get("access_token").asText(); // Retorna o valor de access_token
        } catch (Exception e) {
        	logger.error("Erro ao extrair o token de acesso do JSON: " + e.getMessage(), e);
            throw new CertificateCoreException("Erro ao extrair o token de acesso do JSON: " + e.getMessage(), e);
        }
    }
       
    public  String getStampBase64(String parmString) throws CertificateCoreException {
        try {
        	HttpClient httpClient = HttpClients.createDefault();
            String varEndPoint = TimeStampConfigUtil.getInstance().getApiEndpointUrl()+ "/stamps";
            HttpPost request = new HttpPost(varEndPoint);
            request.setHeader("Authorization", "Bearer " + accessToken);
            request.setHeader("Content-Type", "application/json");
            request.setHeader("accept", "application/json");

            MessageDigest md = MessageDigest.getInstance("SHA-256");
	        byte[] hash = md.digest(parmString.getBytes(StandardCharsets.UTF_8));
	        String base64Hash = Base64.getEncoder().encodeToString(hash);
			String jsonBody = "{\"hash\": \"" + base64Hash + "\"}";
            StringEntity entity = new StringEntity(jsonBody, "UTF-8");

            request.setEntity(entity);
            
            org.apache.http.HttpResponse response = httpClient.execute(request);

            int statusCode = response.getStatusLine().getStatusCode();

            if (statusCode == 200) {
            	return  EntityUtils.toString(response.getEntity());
            } else {
            	logger.error("HTTP Error: " + statusCode);
                throw new CertificateCoreException("HTTP Error: " + statusCode);
            }
        } catch (Exception e) {
        	logger.error("Error connecting to timestamp server:" + e.getMessage());
            throw new CertificateCoreException("Error connecting to timestamp server: " + e.getMessage(), e);
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
	public InputStream authorize(byte[] content) throws UnknownHostException, CertificateCoreException {
        // UNUSED
		return null;
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


}
