package org.demoiselle.signer.timestamp.connector;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import org.demoiselle.signer.timestamp.configuration.TimeStampConfig;
import org.junit.Test;

public class ApiConnectorTest {

	//@Test
	public void testAthenticate() {

	
//		Para utilização no parâmetro Authorization, é necessário concatenar os códigos Consumer Key e Consumer Secret
//		 * separados pelo caracter ":", e converter o resultado em BASE64. 
//		 * No exemplo a seguir, é retornada a string ZGphUjIx[...]IzT3RlCg:
//	     * echo -n "djaR21PGoYp1iyK2n2ACOH9REdUb:ObRsAJWOL4fv2Tp27D1vd8fB3Ote" | base64
		
//		String clientId = "jp9uY0yPgaUlnzT7peffj1SAiw8a";
//		String clientSecret = "XfmCTljA9mzG9VfRuf_1yPf3gSga";
			
		
		TimeStampConfig.getInstance().setClientCredentials("anA5dVkweVBnYVVsbnpUN3BlZmZqMVNBaXc4YTpYZm1DVGxqQTltekc5VmZSdWZfMXlQZjNnU2dh");
		ApiConnector connector = new ApiConnector();
		// ZGphUjIxUEdvWXAxaXlLMm4yQUNPSDlSRWRVYjpPYlJzQUpXT0w0ZnYyVHAyN0QxdmQ4ZkIzT3Rl
		String accessToken = connector.getAccessToken();
		System.out.println(accessToken);
		assertNotNull(accessToken);
	}

	//@Test
	public void testGetStampBase64() {

		TimeStampConfig.getInstance().setClientCredentials("anA5dVkweVBnYVVsbnpUN3BlZmZqMVNBaXc4YTpYZm1DVGxqQTltekc5VmZSdWZfMXlQZjNnU2dh");
		String parmTeste = "Testando TimeStamp API";
		ApiConnector connector = new ApiConnector();
		String stampBase64 = connector.getStampBase64(parmTeste);
		System.out.println(stampBase64);
		assertNotNull(stampBase64);

	}
	
	//@Test
	public void testGetDecodedStamps() {
		
		TimeStampConfig.getInstance().setClientCredentials("anA5dVkweVBnYVVsbnpUN3BlZmZqMVNBaXc4YTpYZm1DVGxqQTltekc5VmZSdWZfMXlQZjNnU2dh");
		String parmTeste = "Testando TimeStamp API";
		ApiConnector connector = new ApiConnector();
		String stampDecoded = connector.getDecodedStamps(parmTeste);
		System.out.println(stampDecoded);
		assertNotNull(stampDecoded);

	}
	
	//@Test
	public void testGetStampForContent() {

		String fileDirName = "/home/emerson/Documentos/teste_carimbo/teste_carimbo.txt";
		byte[] content = readContent(fileDirName);
		TimeStampConfig.getInstance().setClientCredentials("anA5dVkweVBnYVVsbnpUN3BlZmZqMVNBaXc4YTpYZm1DVGxqQTltekc5VmZSdWZfMXlQZjNnU2dh");
		ApiConnector connector = new ApiConnector();
		byte[] timeStampForContent = connector.getStampForContent(content);
		assertNotNull(timeStampForContent);
	}

	private byte[] readContent(String parmFile) {
		byte[] result = null;
		try {
			File file = new File(parmFile);
			FileInputStream is = new FileInputStream(parmFile);
			result = new byte[(int) file.length()];
			is.read(result);
			is.close();
		} catch (IOException ex) {
			ex.printStackTrace();
		}
		return result;
	}
}
