package org.demoiselle.signer.timestamp.connector;

import static org.junit.Assert.assertNotNull;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
//import org.junit.Test;

public class ApiConnectorTest {

	//@Test
	public void testAthenticate() {

		try {

//		Para utilização no parâmetro Authorization, é necessário concatenar os códigos Consumer Key e Consumer Secret
//		 * separados pelo caracter ":", e converter o resultado em BASE64. 
//		 * No exemplo a seguir, é retornada a string ZGphUjIx[...]IzT3RlCg:
//	     * echo -n "djaR21PGoYp1iyK2n2ACOH9REdUb:ObRsAJWOL4fv2Tp27D1vd8fB3Ote" | base64

			// Credenciais para utilizar a API de Carimbo do Tempo do SERPRO
			// TimeStampConfig.getInstance().setClientCredentials("de acordo com a
			// documentação:
			// https://doc-apitimestamp.estaleiro.serpro.gov.br/quick_start/#como-autenticar-na-api-carimbo-do-tempo");
			// ou as variáveis de ambiente SIGNER_TIMESTAMP_API_SERPRO=true e
			// SIGNER_TIMESTAMP_CLIENT_CREDENTIALS
			ApiConnector connector = new ApiConnector();
			String accessToken = connector.getAccessToken();
			System.out.println(accessToken);
			assertNotNull(accessToken);

		} catch (Exception e) {
			e.printStackTrace();
			assertNotNull(null);
			// TODO: handle exception
		}

	}

//	@Test
	public void testGetStampBase64() {

		// Credenciais para utilizar a API de Carimbo do Tempo do SERPRO
		// TimeStampConfig.getInstance().setClientCredentials("de acordo com a
		// documentação:
		// https://doc-apitimestamp.estaleiro.serpro.gov.br/quick_start/#como-autenticar-na-api-carimbo-do-tempo");
		// ou as variáveis de ambiente SIGNER_TIMESTAMP_API_SERPRO=true e
		// SIGNER_TIMESTAMP_CLIENT_CREDENTIALS
		String parmTeste = "Testando TimeStamp API";
		ApiConnector connector = new ApiConnector();
		String stampBase64 = connector.getStampBase64(parmTeste);
		System.out.println(stampBase64);
		assertNotNull(stampBase64);

	}

	// @Test
	public void testGetDecodedStamps() {

		// Credenciais para utilizar a API de Carimbo do Tempo do SERPRO
		// TimeStampConfig.getInstance().setClientCredentials("de acordo com a
		// documentação:
		// https://doc-apitimestamp.estaleiro.serpro.gov.br/quick_start/#como-autenticar-na-api-carimbo-do-tempo");
		// ou as variáveis de ambiente SIGNER_TIMESTAMP_API_SERPRO=true e
		// SIGNER_TIMESTAMP_CLIENT_CREDENTIALS
		String parmTeste = "Testando TimeStamp API";
		ApiConnector connector = new ApiConnector();
		String stampDecoded = connector.getDecodedStamps(parmTeste);
		System.out.println(stampDecoded);
		assertNotNull(stampDecoded);

	}

	// @Test
	public void testGetStampForContent() {

		String fileDirName = "/";
		byte[] content = readContent(fileDirName);
		// Credenciais para utilizar a API de Carimbo do Tempo do SERPRO
		// TimeStampConfig.getInstance().setClientCredentials("de acordo com a
		// documentação:
		// https://doc-apitimestamp.estaleiro.serpro.gov.br/quick_start/#como-autenticar-na-api-carimbo-do-tempo");
		// ou as variáveis de ambiente SIGNER_TIMESTAMP_API_SERPRO=true e
		// SIGNER_TIMESTAMP_CLIENT_CREDENTIALS
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
