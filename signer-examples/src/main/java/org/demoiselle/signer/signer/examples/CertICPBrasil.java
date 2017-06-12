package org.demoiselle.signer.signer.examples;

import org.demoiselle.signer.core.extension.ICPBrasilExtension;
import org.demoiselle.signer.core.extension.ICPBrasilExtensionType;

public class CertICPBrasil {

	@ICPBrasilExtension(type = ICPBrasilExtensionType.CPF)
	private String cpf;

	@ICPBrasilExtension(type = ICPBrasilExtensionType.NAME)
	private String nome;

	public String getCpf() {
		return cpf;
	}

	public String getNome() {
		return nome;
	}

}
