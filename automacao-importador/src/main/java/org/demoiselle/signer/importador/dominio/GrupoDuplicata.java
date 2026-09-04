package org.demoiselle.signer.importador.dominio;

import java.util.List;

/**
 * Grupo de certificados que constituem uma Duplicata_Exata: todos possuem o
 * mesmo {@code serial} e o mesmo {@code subject} (mesma {@link Certificado#identidade()}).
 *
 * <p>Um {@code GrupoDuplicata} sempre contem mais de um certificado (o detector
 * so reporta grupos com tamanho maior que 1). A {@code identidade} e a chave
 * compartilhada pelos membros do grupo.</p>
 *
 * @param identidade a identidade {@code serial|subject} comum a todos os membros
 * @param membros    os certificados do grupo (tamanho maior que 1), na ordem de entrada
 */
public record GrupoDuplicata(
        String identidade,
        List<Certificado> membros
) {}
