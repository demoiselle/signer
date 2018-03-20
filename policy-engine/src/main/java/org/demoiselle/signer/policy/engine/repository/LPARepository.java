package org.demoiselle.signer.policy.engine.repository;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

import org.demoiselle.signer.core.util.Downloads;

/**
 * 
 * Class to persist LPA file on local directory
 *
 */
public class LPARepository {

	public static final String PATH_HOME_USER = System.getProperty("user.home");
	public static final String FOLDER_SIGNER = ".signer";
	public static final Path FULL_PATH_FOLDER_SIGNER = Paths.get(PATH_HOME_USER, FOLDER_SIGNER);
	
	/**
	 * 
	 * to save file on user local directory 
	 * 
	 * @param urlConLPA Url for get the LPA file 
	 * @param lpaName the name of file to be saved
	 * @return true if file was saved
	 */
	
	public static boolean saveLocalLPA(final String urlConLPA, final String lpaName) {
		
		Path pathLPA = Paths.get(PATH_HOME_USER, FOLDER_SIGNER, lpaName);
		try {
			
			InputStream is = Downloads.getInputStreamFromURL(urlConLPA);	
			Files.copy(is, pathLPA, StandardCopyOption.REPLACE_EXISTING);
			is.close();
			return true;
		} catch (FileNotFoundException e) {			
			e.printStackTrace();
			return false;
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}		
	}	
}




