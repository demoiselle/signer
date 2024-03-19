package org.demoiselle.signer.policy.impl.pades.pkcs7.impl;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.junit.Test;

@SuppressWarnings("unused")
public class PDFtoHex {

	private InputStream is;

	//@Test
	public void test() throws IOException {
		
			File file = new File("/home/emerson/Downloads/teste_pgfn.pdf");

		    is = new BufferedInputStream(new FileInputStream(file));

		    int value = 0;
		    StringBuilder hex = new StringBuilder();

		    while ((value = is.read()) != -1) {
		        hex.append(String.format("%02X", value));
		    	//hex.append( value);

		    }
		    System.out.println(hex.toString());
		}
	
	//@Test
	public void hexStringToByteArray() throws IOException {
		
		String s = "85D6A9D6BAB5FA2469C4C93D72D2682D664A669516D4D9D49F56C0458ABF9C20";
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    
	    File file = new File("/home/emerson/Downloads/hextofile.pdf");
		FileOutputStream os = new FileOutputStream(file);
		os.write(data);
		os.flush();
		os.close();

	}

}
