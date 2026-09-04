package org.demoiselle.signer.importador.nucleo;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.demoiselle.signer.importador.dominio.AtribuicaoAlias;
import org.demoiselle.signer.importador.dominio.Certificado;

/**
 * Geracao pura de aliases unicos e determinsticos para os certificados a serem
 * gravados no keystore.
 *
 * <p>Para cada certificado, deriva um alias base a partir do CN (normalizado
 * para um identificador estavel: minusculas, remocao de acentos e substituicao
 * de qualquer caractere nao alfanumerico por {@code '-'}). Ao colidir de forma
 * case-insensitive com um alias ja atribuido, gera um alias alternativo
 * deterministico (base + sufixo derivado do serial e, se ainda colidir, um
 * contador estavel).</p>
 *
 * <p>Garantias:</p>
 * <ul>
 *   <li><b>Determinismo</b>: a mesma entrada (mesma ordem) produz sempre a
 *   mesma saida.</li>
 *   <li><b>Unicidade case-insensitive</b>: todos os {@code aliasFinal} sao
 *   distintos quando comparados via {@link String#equalsIgnoreCase(String)}.</li>
 * </ul>
 *
 * <p>Funcao pura, sem IO. Os certificados sao processados na ordem recebida.</p>
 */
public final class GeradorAlias {

    /** Alias base default quando o CN nao produz um identificador utilizavel. */
    private static final String BASE_DEFAULT = "cert";

    private GeradorAlias() {
    }

    /**
     * Gera as atribuicoes de alias para a lista de certificados informada.
     *
     * @param certs lista de certificados (processados na ordem recebida); nao nula
     * @return lista de {@link AtribuicaoAlias}, uma por certificado, com aliases
     *         finais unicos case-insensitive
     */
    public static List<AtribuicaoAlias> gerarAliases(List<Certificado> certs) {
        List<AtribuicaoAlias> atribuicoes = new ArrayList<>(certs.size());
        Set<String> usadosLower = new HashSet<>();

        for (Certificado cert : certs) {
            String base = derivarBase(cert);
            String aliasFinal = resolverColisao(base, cert, usadosLower);
            usadosLower.add(aliasFinal.toLowerCase(Locale.ROOT));
            atribuicoes.add(new AtribuicaoAlias(cert, base, aliasFinal));
        }

        return atribuicoes;
    }

    /**
     * Resolve a colisao case-insensitive de um alias base de forma
     * deterministica: usa o base se disponivel; senao concatena um sufixo
     * derivado do serial; se ainda colidir, adiciona um contador estavel.
     */
    private static String resolverColisao(String base, Certificado cert, Set<String> usadosLower) {
        if (!usadosLower.contains(base.toLowerCase(Locale.ROOT))) {
            return base;
        }

        String sufixoSerial = derivarSufixoSerial(cert);
        String candidato = base + "-" + sufixoSerial;
        if (!usadosLower.contains(candidato.toLowerCase(Locale.ROOT))) {
            return candidato;
        }

        int contador = 2;
        String comContador;
        do {
            comContador = candidato + "-" + contador;
            contador++;
        } while (usadosLower.contains(comContador.toLowerCase(Locale.ROOT)));
        return comContador;
    }

    /**
     * Deriva um alias base estavel a partir do CN: normaliza acentos, converte
     * para minusculas e substitui caracteres nao alfanumericos por {@code '-'}.
     * Se o resultado for vazio, usa um base default estavel derivado do serial.
     */
    private static String derivarBase(Certificado cert) {
        String cn = cert.cn();
        String normalizado = normalizarIdentificador(cn);
        if (normalizado.isEmpty()) {
            return BASE_DEFAULT + "-" + derivarSufixoSerial(cert);
        }
        return normalizado;
    }

    /**
     * Normaliza um texto para um identificador estavel: remove acentos, converte
     * para minusculas (Locale.ROOT), troca qualquer sequencia de caracteres nao
     * alfanumericos por um unico {@code '-'} e remove hifens nas extremidades.
     */
    private static String normalizarIdentificador(String texto) {
        if (texto == null) {
            return "";
        }
        String semAcento = java.text.Normalizer.normalize(texto, java.text.Normalizer.Form.NFD)
                .replaceAll("\\p{M}+", "");
        String minusculas = semAcento.toLowerCase(Locale.ROOT);
        String hifenizado = minusculas.replaceAll("[^a-z0-9]+", "-");
        return trimHifens(hifenizado);
    }

    /** Remove hifens no inicio e no fim sem depender de regex extra. */
    private static String trimHifens(String s) {
        int inicio = 0;
        int fim = s.length();
        while (inicio < fim && s.charAt(inicio) == '-') {
            inicio++;
        }
        while (fim > inicio && s.charAt(fim - 1) == '-') {
            fim--;
        }
        return s.substring(inicio, fim);
    }

    /**
     * Deriva um sufixo estavel a partir do serial do certificado. O serial e um
     * BigInteger; usamos sua representacao decimal (canonica e deterministica).
     * Trata serial nulo com um marcador estavel.
     */
    private static String derivarSufixoSerial(Certificado cert) {
        return cert.serial() == null ? "sem-serial" : cert.serial().toString();
    }
}
