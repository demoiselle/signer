package org.demoiselle.signer.core.util;

import java.text.MessageFormat;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

public class MessagesBundle {

	
	private String bundleName = "messages";
	private static ResourceBundle resouceBundle; 
	
	
	public MessagesBundle() {
		super();
		MessagesBundle.setResouceBundle(ResourceBundle.getBundle(this.bundleName));
	}
	

	public MessagesBundle(String parmBundleName) {
		super();
		this.bundleName = parmBundleName;
		MessagesBundle.setResouceBundle(ResourceBundle.getBundle(this.bundleName));
	}

	public String getString(String key) {
		try {
			return getResouceBundle().getString(key);
		} catch (MissingResourceException e) {
			return '!' + key + '!';
		}
	}

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