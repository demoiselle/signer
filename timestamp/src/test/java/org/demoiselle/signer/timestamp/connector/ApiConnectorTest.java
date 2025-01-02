package org.demoiselle.signer.timestamp.connector;

import static org.junit.Assert.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.io.InputStream;
import org.junit.Test;
import java.util.Base64;

public class ApiConnectorTest {

	//@Test
	public void testAthenticate() {

	  String clientCredentials = "ZGphUjIxUEdvWXAxaXlLMm4yQUNPSDlSRWRVYjpPYlJzQUpXT0w0ZnYyVHAyN0QxdmQ4ZkIzT3RlCg";
      ApiConnector connector = new ApiConnector(clientCredentials);
      //ZGphUjIxUEdvWXAxaXlLMm4yQUNPSDlSRWRVYjpPYlJzQUpXT0w0ZnYyVHAyN0QxdmQ4ZkIzT3Rl
      String accessToken = connector.getAccessToken();
      System.out.println(accessToken);
      assertNotNull(accessToken);
	}
	
	@Test
	public void testGetStampBase64() {
		
		// gera o hash do arquivo
		try {
			String clientCredentials = "ZGphUjIxUEdvWXAxaXlLMm4yQUNPSDlSRWRVYjpPYlJzQUpXT0w0ZnYyVHAyN0QxdmQ4ZkIzT3RlCg";
			String parmTeste = "Testando TimeStamp API";
			MessageDigest md = MessageDigest.getInstance("SHA-256");
	        byte[] hash = md.digest(parmTeste.getBytes(StandardCharsets.UTF_8));
	        String base64Hash = Base64.getEncoder().encodeToString(hash);
			//String jsonBody = "{\"hash\": \"almR/QW61AVNHRZBf95t1udeN61370sNpjO2ybKiUHY=\"}";
			String jsonBody = "{\"hash\": \"" + base64Hash + "\"}";
		    ApiConnector connector = new ApiConnector(clientCredentials);
		    String connected =  connector.getStampBase64(jsonBody);
		    System.out.println(connected);
		    assertNotNull(connected);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

      
	}
}
