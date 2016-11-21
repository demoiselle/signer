package org.demoiselle.signer.example.token;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

//Nesse exemplo gerenciamos em memória, mas ele pode ser gerenciado em banco e com timeout
public class TokenManager {
	
	private static Map<String,  Map<String, String>> map = Collections.synchronizedMap(new HashMap<String, Map<String, String>>());

	public static String put(Map<String, String> files) {
		String token = UUID.randomUUID().toString();

		map.put(token,files);
		return token;
	}

	public static Map<String, String> get(String token) {
		return map.get(token);
	}

	public static void invalidate(String token) {
		map.remove(token);
	}
	
	public static boolean isValid(String token){
		return map.containsKey(token);
	}

}
