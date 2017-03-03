package org.demoiselle.signer.agent.desktop.command;

import java.lang.reflect.ParameterizedType;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.demoiselle.signer.agent.desktop.Command;
import org.demoiselle.signer.core.util.Base64Utils;

import com.google.gson.Gson;

public abstract class AbstractCommand<Request, Response> implements Command {

	private static final String ERROR_MESSAGE = "{\"erro\" : \"Erro ao tentar interpretar "
			+ "os parametros do comando.\" }";

	public abstract Response doCommand(Request request);

	public String getCommandName() {
		return this.getClass().getSimpleName().toLowerCase();
	}

	@SuppressWarnings("unchecked")
	public String doCommand(String params) {
		Security.addProvider(new BouncyCastleProvider());

		Gson gson = new Gson();
		Request request = null;
		try {
			Class<Request> type = (Class<Request>) ((ParameterizedType) getClass().getGenericSuperclass())
					.getActualTypeArguments()[0];
			request = gson.fromJson(params, type);
		} catch (Throwable errorData) {
			return AbstractCommand.ERROR_MESSAGE;
		}
		if (request == null)
			return AbstractCommand.ERROR_MESSAGE;
		try {
			Response response = this.doCommand(request);
			String resultJson = gson.toJson(response);
			return resultJson;
		} catch (Throwable error) {
			return "{\"error\": \"" + error.getMessage() + "\"}";
		}
	}
	
	public byte[] contentToBytes(String content, String format) {
		return contentToBytes(content, format, false);
	}
	
	public byte[] contentToBytes(String content, String format, boolean compacted) {
		byte[] result = null;
		
		if (content == null)
			return null;

		if (format == null)
			format = "text";
		
		if (format.equalsIgnoreCase("text")) {
			// if format text, don't needed to be
			// descompacted, return from here
			return content.getBytes();
		} else if ("base64".equalsIgnoreCase(format)) {
			try {
				result = Base64Utils.base64Decode(content);
			} catch (Throwable error) {
				throw new RuntimeException("Error decoding content", error);
			}
		} else if (format.equalsIgnoreCase("hexa")) {
		    int len = content.length();
		    byte[] data = new byte[len / 2];
		    for (int i = 0; i < len; i += 2) {
		        data[i / 2] = (byte) ((Character.digit(content.charAt(i), 16) << 4)
		                             + Character.digit(content.charAt(i+1), 16));
		    }
		    result = data;
		}
		// For others formats that may be compacted
		// TODO: algorithm to unzip content
		if (compacted) {
		}
		
		return result;
	}
	
}