/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.demoiselle.signer.example.rest;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;

import org.demoiselle.signer.example.token.TokenManager;


@Path("token")
public class TokenREST {

	private static final Logger LOGGER = Logger.getLogger(TokenREST.class.getName());
	
    @GET
    @Path("generate/{info}")
    @Produces("text/plain")
    public String generate(@PathParam("info") String info) {
    	
    	Map<String, String> files = Collections.synchronizedMap(new HashMap<String, String>());
    	for (String nameFiles : info.split(",")) {
			files.put(nameFiles, null);
		}
    	
    	String token = TokenManager.put(files);
    	LOGGER.log(Level.INFO, "Token Criado: " + token);
        return token;
    }
    
    @GET
    @Path("validate/{info}")
    @Produces("text/plain")
    public boolean validate(@PathParam("info") String info) {
    	LOGGER.log(Level.INFO, "Validar token: " + info);
        return TokenManager.isValid(info);
    }
    
}
