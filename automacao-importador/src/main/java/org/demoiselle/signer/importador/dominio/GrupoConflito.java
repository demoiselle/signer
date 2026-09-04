package org.demoiselle.signer.importador.dominio;

import java.util.List;

/**
 * Grupo de certificados que constituem um Conflito_De_Case: todos compartilham
 * o mesmo {@code cnNorm} (CN comparado de forma case-insensitive), porem o grupo
 * contem mais de uma grafia distinta de CN (por exemplo "Hom" vs "HOM").
 *
 * <p>Este grupo nao deve ser confundido com {@link GrupoDuplicata}: um conflito de
 * case pressupoe grafias diferentes de CN (valores de {@code cn} distintos, mesmo
 * {@code cnNorm}). O detector so reporta grupos que contenham ao menos duas grafias
 * distintas de CN.</p>
 *
 * @param cnNorm      o CN normalizado (case-insensitive) comum a todos os membros
 * @param certificados os certificados do grupo, na ordem de entrada
 */
public record GrupoConflito(
        String cnNorm,
        List<Certificado> certificados
) {}
