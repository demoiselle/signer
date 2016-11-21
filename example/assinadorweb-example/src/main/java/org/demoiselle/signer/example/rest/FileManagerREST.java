package org.demoiselle.signer.example.rest;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletContext;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.Response.Status;

import org.demoiselle.signer.example.token.TokenManager;

import org.demoiselle.signer.signature.signer.factory.PKCS7Factory;
import org.demoiselle.signer.signature.signer.pkcs7.PKCS7Signer;
import br.gov.frameworkdemoiselle.certificate.signer.pkcs7.bc.policies.ADRBCMS_2_1;
import org.demoiselle.signer.signature.core.util.ZipBytes;

@Path("filemanager")
public class FileManagerREST {
	
	private static final Logger LOGGER = Logger.getLogger(FileManagerREST.class.getName());

	private final String SERVER_DOWNLOAD_LOCATION_FOLDER = "file/source/";
	private final String SERVER_UPLOAD_LOCATION_FOLDER = "file/signature/";
	private final String SIGNATURE_EXTENSION = ".p7s";
	private final String SIGNATURE_ZIP = ".zip";
	private final int FILE_BUFFER_SIZE = 4096;

	@Context
	ServletContext context;

	@Context
	HttpHeaders headers;


	/**
	 * Implementar um serviço para download de arquivo zip e esperar um Token válido
	 * **/
	@GET
	@Path("download")
	@Produces("application/zip")
	public Response download() throws IOException {
		LOGGER.log(Level.INFO,"br.gov.serpro.jnlp.rest.FileManagerREST.download()");

		String downloadLocation = context.getRealPath("").concat(File.separator).concat(SERVER_DOWNLOAD_LOCATION_FOLDER);
		byte[] content = null;
		ResponseBuilder response = null;
		Map<String, byte[]> files = Collections	.synchronizedMap(new HashMap<String, byte[]>());

		String token = getToken();

		if (TokenManager.isValid(token)) {

			// Buscar arquivos associados ao Token
			for (Map.Entry<String, String> filesToSign : TokenManager.get(token).entrySet()) {
				java.nio.file.Path path = Paths.get(downloadLocation.concat(filesToSign.getKey()));
				content = Files.readAllBytes(path);

				files.put(filesToSign.getKey(), content);
			}

			byte[] zipFiles = ZipBytes.compressing(files);

			response = Response.ok((Object) zipFiles);
			response.header("Content-Type", "application/zip");
			response.header("Content-Disposition", "attachment; filename="+ token + ".zip");
		}else{
			response = Response.status(Status.UNAUTHORIZED);
		}
		return response.build();
	}

	/**
	 * Implementar método para upload de arquivo zip e esperar um Token válido
	 * 
	 * **/
	@POST
	@Path("upload")
	@Consumes("application/zip")
	public Response upload(InputStream payload) {
		LOGGER.log(Level.INFO,"br.gov.serpro.jnlp.rest.FileManagerREST.upload()");
		
		String uploadLocation = context.getRealPath("").concat(File.separator).concat(SERVER_UPLOAD_LOCATION_FOLDER);

		Map<String, byte[]> signatures = Collections.synchronizedMap(new HashMap<String, byte[]>());
		ResponseBuilder response = null;

		String token = getToken();

		if (TokenManager.isValid(token)) {

			try {
				File directory = new File(uploadLocation);
				if (!directory.exists()) {
					if (directory.mkdirs()) {
						LOGGER.log(Level.INFO,"Multiple directories are created.");
					} else {
						LOGGER.log(Level.WARNING,"Failed to create multiple directories.");
					}
				}

				ByteArrayOutputStream ba = new ByteArrayOutputStream();
				byte[] buffer = new byte[FILE_BUFFER_SIZE];

				int bytesRead = -1;

				while ((bytesRead = payload.read(buffer)) != -1) {
					ba.write(buffer, 0, bytesRead);
				}
				ba.flush();
				ba.close();
				LOGGER.log(Level.INFO,"Dados recebidos.");

				Calendar calendar = new GregorianCalendar();
				DateFormat df = new SimpleDateFormat("yyyyMMdd_HHmmssSSS");

				java.nio.file.Path path = Paths.get(uploadLocation.concat(df.format(calendar.getTime())).concat(SIGNATURE_ZIP));

				signatures = ZipBytes.decompressing(ba.toByteArray());
				for (Map.Entry<String, byte[]> entry : signatures.entrySet()) {
					String nameSignature = entry.getKey().concat("-").concat(df.format(calendar.getTime())).concat(SIGNATURE_EXTENSION);
					path = Paths.get(uploadLocation.concat(nameSignature));
					Files.write(path, entry.getValue(), StandardOpenOption.CREATE);
					//Salvar assianturas relacionada com seus respectivos arquivos
					TokenManager.get(token).put(entry.getKey(),	nameSignature);
				}

			} catch (IOException ex) {
				LOGGER.log(Level.SEVERE, null, ex);
			}
			
			//Checar as assinaturas e arquivos associados a um Token
			check(token);
			//Descartar esse Token
			TokenManager.invalidate(token);
			//Enviar resposta de OK a quem chamou o serviço
			response = Response.status(Status.NO_CONTENT);
			//Enviar resposta de ASSINADOS a janela HTML
		}else{
			response = Response.status(Status.UNAUTHORIZED);
		}

		return response.build();
	}
	
	@POST
	@Path("cancelar")
	@Consumes("application/octet-stream")
	public Response cancel(InputStream payload) {
		LOGGER.log(Level.INFO,"br.gov.serpro.jnlp.rest.FileManagerREST.cancel()");
		
		ResponseBuilder response = null;
		String token = getToken();
		String message = "";

		if (TokenManager.isValid(token)) {
			try {
				
				StringBuilder inputStringBuilder = new StringBuilder();
		        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(payload, "UTF-8"));
		        String line = bufferedReader.readLine();
		        while(line != null){
		            inputStringBuilder.append(line);inputStringBuilder.append('\n');
		            line = bufferedReader.readLine();
		        }
		        message = inputStringBuilder.toString();

			} catch (IOException ex) {
				Logger.getLogger(FileManagerREST.class.getName()).log(Level.SEVERE, null, ex);
			}
			//Descartar Token
			TokenManager.invalidate(token);
			// Enviar mensagem para tela
			LOGGER.log(Level.INFO,"Mensagem de cancelamento: " + message);
			
			response = Response.status(Status.NO_CONTENT);
			
		}else{
			response = Response.status(Status.UNAUTHORIZED);
		}
		
		return response.build();
	}
	
	//Método para checar no servidor as assinatura e arquivos
	private boolean check(String token) {
		String downloadLocation = context.getRealPath("").concat(File.separator).concat(SERVER_DOWNLOAD_LOCATION_FOLDER);
		String uploadLocation = context.getRealPath("").concat(File.separator).concat(SERVER_UPLOAD_LOCATION_FOLDER);

		byte[] file = null;
		byte[] signature = null;

		Iterator entries = TokenManager.get(token).entrySet().iterator();
		while (entries.hasNext()) {
			Entry thisEntry = (Entry) entries.next();
			String nameFile = (String) thisEntry.getKey();
			String nameSignature = (String) thisEntry.getValue();

			LOGGER.log(Level.INFO,"Validar aquivo: " + nameFile);
			java.nio.file.Path pathFile = Paths.get(downloadLocation.concat(nameFile));
			java.nio.file.Path pathSignature = Paths.get(uploadLocation	.concat(nameSignature));

			try {
				file = Files.readAllBytes(pathFile);
				signature = Files.readAllBytes(pathSignature);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
		signer.setSignaturePolicy(new ADRBCMS_2_1());
		signer.check(file, signature);

		return true;

	}
	
	private String getToken(){
		return  headers.getRequestHeader("authorization").get(0).replace("Token ", "");
	}
}
