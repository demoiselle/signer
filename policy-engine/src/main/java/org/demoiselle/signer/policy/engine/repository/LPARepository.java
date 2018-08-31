package org.demoiselle.signer.policy.engine.repository;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

import org.apache.log4j.Logger;
import org.demoiselle.signer.core.repository.Configuration;
import org.demoiselle.signer.core.util.Downloads;
import org.demoiselle.signer.policy.engine.util.MessagesBundle;

/**
 * 
 * Class to persist LPA file on local directory
 *
 */
public class LPARepository {
	
	private static MessagesBundle policyMessagesBundle = new MessagesBundle("messages_policy");
	private final static Logger LOGGER = Logger.getLogger(LPARepository.class.getName());
	
	/**
	 * 
	 * to save file on user local directory 
	 * 
	 * @param urlConLPA Url for get the LPA file 
	 * @param lpaName the name of file to be saved
	 * @return true if file was saved
	 */
	
	public static boolean saveLocalLPA(final String urlConLPA, final String lpaName) {
		
		try {
			Configuration config = Configuration.getInstance();
			Path pathLPA = Paths.get(config.getLpaPath());
			Path pathLPAFile = Paths.get(config.getLpaPath(), lpaName);
			
			if (!Files.isDirectory(pathLPA)) {
				LOGGER.info(policyMessagesBundle.getString("warn.lpa.dir.not.found", pathLPA));				
				Files.createDirectories(pathLPA);
			}
			InputStream is = Downloads.getInputStreamFromURL(urlConLPA);	
			Files.copy(is, pathLPAFile, StandardCopyOption.REPLACE_EXISTING);
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




