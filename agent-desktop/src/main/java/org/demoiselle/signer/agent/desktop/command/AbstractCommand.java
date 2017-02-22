package org.demoiselle.signer.agent.desktop.command;

import java.lang.reflect.ParameterizedType;

import org.demoiselle.signer.agent.desktop.Command;

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
}