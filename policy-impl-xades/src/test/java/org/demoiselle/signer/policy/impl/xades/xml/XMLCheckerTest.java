package org.demoiselle.signer.policy.impl.xades.xml;

import static org.junit.Assert.*;

import java.io.File;
import java.net.URL;

import org.junit.Test;

public class XMLCheckerTest {

	@Test
	public void test() {
		
		try {
			String fileName = "teste_assinatura_rt_signed.xml";
			
	        ClassLoader classLoader = getClass().getClassLoader();
	        URL fileUri = classLoader.getResource(fileName);
	        File newFile=new File(fileUri.toURI());
	        
//	        InputStreamReader streamReader = new InputStreamReader(inputStream, StandardCharsets.UTF_8);
//	        BufferedReader reader = new BufferedReader(streamReader); 
	        			
			XMLChecker xadesChecker = new XMLChecker();
			assertTrue(xadesChecker.check(newFile.getPath()));
					
		} catch (Throwable e) {			
		  e.printStackTrace();
		  assertTrue(false);
		}		
	}

}
