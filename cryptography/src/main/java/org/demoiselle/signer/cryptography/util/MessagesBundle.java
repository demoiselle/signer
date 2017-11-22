package org.demoiselle.signer.cryptography.util;

import java.text.MessageFormat;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

/**
 * 
 *  Custom Messages Bundle implementation to allows parameterization
 *
 */
public class MessagesBundle {

	
	private String bundleName = "messages";
	private static ResourceBundle resouceBundle; 
	
	/**
	 * Default constructor using the messages.properties file 
	 */
	public MessagesBundle() {
		super();
		MessagesBundle.setResouceBundle(ResourceBundle.getBundle(this.bundleName));
	}
	

	/**
	 * 
	 * @param parmBundleName name for a .properties file
	 */
	public MessagesBundle(String parmBundleName) {
		super();
		this.bundleName = parmBundleName;
		ResourceBundle varResourceBundle = ResourceBundle.getBundle(this.bundleName); 
		MessagesBundle.setResouceBundle(varResourceBundle);
	}

	/**
	 * example: getString("key.propertie.name")
	 * 
	 * @param key key to be searched
	 * @return value associated with key
	 */
	public String getString(String key) {
		try {
			return getResouceBundle().getString(key);
		} catch (MissingResourceException e) {
			return '!' + key + '!';
		}
	}

	/**
	 * example: getString("key.propertie.name", parm1, parm2 )
	 * 
	 * @param key key to be searched
	 * @param params values to be substituted
	 * @return string value associated with key
	 */
	public String getString(String key, Object... params) {
		try {
			return MessageFormat.format(getResouceBundle().getString(key), params);
		} catch (MissingResourceException e) {
			return '!' + key + '!';
		}
	}

	public static ResourceBundle getResouceBundle() {
		return resouceBundle;
	}

	public static void setResouceBundle(ResourceBundle resouceBundle) {
		MessagesBundle.resouceBundle = resouceBundle;
	}
}