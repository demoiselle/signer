package org.demoiselle.signer.core.util;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownServiceException;

/**
 * 
 * Class to support downloads
 *
 */
public class Downloads {
	
	private static final int TIMEOUT_CONNECTION = 3000;
	private static final int TIMEOUT_READ = 5000;
	private static MessagesBundle coreMessagesBundle = new MessagesBundle();

	
	/**
	 * execute file download from defined URL 
	 * @param stringURL
	 * @return InputStream
	 * @throws RuntimeException
	 */
	public static InputStream getInputStreamFromURL(final String stringURL) throws RuntimeException {
		try {
			URL url = new URL(stringURL);
			URLConnection connection = url.openConnection();
			connection.setConnectTimeout(TIMEOUT_CONNECTION);
			connection.setReadTimeout(TIMEOUT_READ);
			return connection.getInputStream();
		} catch (MalformedURLException error) {
			throw new RuntimeException(coreMessagesBundle.getString("error.malformedURL"), error);
		} catch (UnknownServiceException error) {
			throw new RuntimeException(coreMessagesBundle.getString("error.unknown.service"), error);
		} catch (IOException error) {
			throw new RuntimeException(coreMessagesBundle.getString("error.io"), error);
		}
	}


}
