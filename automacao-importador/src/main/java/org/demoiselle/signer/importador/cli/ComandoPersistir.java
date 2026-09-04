package org.demoiselle.signer.importador.cli;

import java.io.Console;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

import org.demoiselle.signer.importador.dominio.AtribuicaoAlias;
import org.demoiselle.signer.importador.dominio.Certificado;
import org.demoiselle.signer.importador.dominio.DiffKeystore;
import org.demoiselle.signer.importador.dominio.Manifest;
import org.demoiselle.signer.importador.dominio.MetodoDedup;
import org.demoiselle.signer.importador.dominio.ResultadoDedup;
import org.demoiselle.signer.importador.dominio.ResultadoExecucao;
import org.demoiselle.signer.importador.io.ExpansorCertificados;
import org.demoiselle.signer.importador.io.KeystoreBks;
import org.demoiselle.signer.importador.io.StagingReader;
import org.demoiselle.signer.importador.io.StagingVaziaException;
import org.demoiselle.signer.importador.nucleo.CalculadoraDiff;
import org.demoiselle.signer.importador.nucleo.DecisorExitCode;
import org.demoiselle.signer.importador.nucleo.DecisorGravacao;
import org.demoiselle.signer.importador.nucleo.Deduplicador;
import org.demoiselle.signer.importador.nucleo.GeradorAlias;
import org.demoiselle.signer.importador.relatorio.RelatorioPersistenciaBuilder;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;
import picocli.CommandLine.Model.CommandSpec;

/**
 * Subcomando {@code persistir}: le a Staging e grava os certificados no
 * Keystore_Final BKS, com deduplicacao configuravel.
 *
 * <p><b>Escopo desta classe (Task 15.1):</b> declaracao das opcoes de CLI,
 * validacao da flag {@code --remover-duplicadas} e o texto de ajuda
 * ({@code -h}/{@code --help}). O fluxo principal de persistencia
 * (carregar staging, snapshot, dedup, gravacao atomica, relatorio, exit code)
 * sera implementado na Task 15.2, preenchendo o corpo de {@link #call()}.
 *
 * <p>Os campos {@code metodoDedup}, {@code keystore}, {@code senha} e
 * {@code staging} sao expostos via getters para uso pela Task 15.2.
 *
 * <p>Requisitos atendidos por esta task: 4.1, 4.2, 4.3, 5.1, 5.2, 5.3.
 */
@Command(
        name = "persistir",
        description = {
                "Le a Staging e grava os certificados no keystore BKS de destino, "
                        + "com deduplicacao configuravel, escrita atomica e relatorio de persistencia.",
                "",
                "Metodos de deduplicacao (--remover-duplicadas):",
                "  1 = Metodo_Conservador (padrao): remove apenas duplicatas exatas "
                        + "(mesmo serial e mesmo subject). Conflitos de case (mesmo CN "
                        + "case-insensitive com grafias distintas) permanecem no keystore.",
                "  2 = Metodo_Agressivo: agrupa os certificados por CN comparado de forma "
                        + "case-insensitive e mantem apenas um por grupo (o de Not_Before "
                        + "mais recente; empate -> o primeiro encontrado). Certificados "
                        + "distintos de mesmo CN podem ser descartados.",
                "",
                "A ajuda (-h/--help) nao baixa, nao deduplica e nao modifica o keystore."
        },
        mixinStandardHelpOptions = true,
        sortOptions = false
)
public class ComandoPersistir implements Callable<Integer> {

    /** Default sensato para o keystore de destino (diretorio corrente). */
    static final String KEYSTORE_DEFAULT = "cadeiasicpbrasil.bks";
    /** Default sensato para a senha do keystore (senha usada hoje no projeto). */
    static final String SENHA_DEFAULT = "serprosigner";
    /** Default sensato para o diretorio de staging (diretorio corrente). */
    static final String STAGING_DEFAULT = "staging";

    @Spec
    CommandSpec spec;

    /**
     * Valor bruto da flag {@code --remover-duplicadas} (1 = conservador, 2 = agressivo).
     * A validacao {1,2} e feita no setter, rejeitando valores invalidos antes de
     * qualquer gravacao (Req 4.1, 4.2, 4.3).
     */
    private int remocaoDuplicadas = 1;

    /** Caminho do arquivo BKS de destino (--keystore), com default sensato. */
    @Option(
            names = {"--keystore"},
            paramLabel = "<arquivo>",
            description = {
                    "Caminho do arquivo BKS de destino (Keystore_Final).",
                    "Default: ${DEFAULT-VALUE} (no diretorio corrente)."
            },
            defaultValue = KEYSTORE_DEFAULT
    )
    private Path keystore = Paths.get(KEYSTORE_DEFAULT);

    /** Senha do keystore de destino (--senha), com default sensato. */
    @Option(
            names = {"--senha"},
            paramLabel = "<senha>",
            description = {
                    "Senha do keystore BKS de destino.",
                    "Default: a senha padrao do projeto (pode ser sobrescrita)."
            },
            defaultValue = SENHA_DEFAULT,
            arity = "1"
    )
    private char[] senha = SENHA_DEFAULT.toCharArray();

    /** Diretorio de staging (--staging), com default sensato. */
    @Option(
            names = {"--staging"},
            paramLabel = "<dir>",
            description = {
                    "Diretorio da Staging de onde os certificados serao lidos.",
                    "Default: ${DEFAULT-VALUE} (no diretorio corrente)."
            },
            defaultValue = STAGING_DEFAULT
    )
    private Path staging = Paths.get(STAGING_DEFAULT);

    /**
     * Setter da flag {@code --remover-duplicadas} com validacao {1,2}.
     * Um valor diferente de 1 e 2 e rejeitado com {@link CommandLine.ParameterException},
     * fazendo o picocli abortar a execucao antes de qualquer gravacao no keystore
     * (Req 4.3).
     */
    @Option(
            names = {"--remover-duplicadas"},
            paramLabel = "<1|2>",
            description = {
                    "Metodo de deduplicacao a aplicar antes de gravar no keystore.",
                    "1 = Metodo_Conservador (padrao): remove apenas duplicatas exatas; "
                            + "conflitos de case permanecem.",
                    "2 = Metodo_Agressivo: agrupa por CN case-insensitive, mantem o "
                            + "Not_Before mais recente e pode descartar certificados "
                            + "distintos de mesmo CN.",
                    "Default: ${DEFAULT-VALUE}."
            },
            defaultValue = "1"
    )
    public void setRemocaoDuplicadas(int valor) {
        if (valor != 1 && valor != 2) {
            throw new CommandLine.ParameterException(
                    spec.commandLine(),
                    "Valor invalido para --remover-duplicadas: " + valor
                            + ". Valores aceitos: 1 (conservador) ou 2 (agressivo).");
        }
        this.remocaoDuplicadas = valor;
    }

    /** Valor bruto da flag {@code --remover-duplicadas} (1 ou 2). */
    public int getRemocaoDuplicadas() {
        return remocaoDuplicadas;
    }

    /**
     * Metodo de deduplicacao selecionado, mapeado a partir da flag
     * {@code --remover-duplicadas}: 1 -&gt; CONSERVADOR, 2 -&gt; AGRESSIVO.
     */
    public MetodoDedup getMetodoDedup() {
        return remocaoDuplicadas == 2 ? MetodoDedup.AGRESSIVO : MetodoDedup.CONSERVADOR;
    }

    /** Caminho do keystore BKS de destino (opcao --keystore). */
    public Path getKeystore() {
        return keystore;
    }

    /** Senha do keystore de destino (opcao --senha). */
    public char[] getSenha() {
        return senha;
    }

    /** Diretorio de staging (opcao --staging). */
    public Path getStaging() {
        return staging;
    }

    /**
     * Fluxo principal de persistencia (Task 15.2).
     *
     * <p>Orquestra: carregar staging (vazia -&gt; aborta "rode baixar primeiro",
     * keystore intacto, exit != 0); ler o manifest e os X.509 reais da staging;
     * snapshot ANTES; deduplicacao conforme {@code --remover-duplicadas};
     * geracao de aliases unicos; decisao de gravacao apos falhas de download
     * (default "nao"; sem TTY -&gt; "nao"); gravacao atomica com rollback (em falha,
     * NAO emite o relatorio); em sucesso, snapshot DEPOIS + diff +
     * Relatorio_Persistencia; e, por fim, traduz o {@link ResultadoExecucao} em
     * exit code via {@link DecisorExitCode}.</p>
     *
     * <p>Erros esperados viram exit != 0 com mensagem concisa (sem stack trace cru
     * para o operador).</p>
     *
     * <p>Requisitos: 1.5, 1.6, 1.7, 4.4, 4.5, 4.6, 6.2, 6.3, 7.2, 7.3, 7.4, 7.5,
     * 8.1, 8.5, 10.1, 10.8, 9.1, 9.2.</p>
     */
    @Override
    public Integer call() throws Exception {
        // 1) Carregar a staging. Staging vazia -> abortar sem tocar no keystore (Req 1.6).
        StagingReader reader = new StagingReader(staging);
        Manifest manifest;
        try {
            manifest = reader.lerManifest();
        } catch (StagingVaziaException e) {
            return abortar("persistir",
                    "Staging vazia em " + staging + ". Rode 'baixar' primeiro. Keystore nao modificado.");
        }

        // 2) Ler os X.509 reais referenciados no manifest, associando-os aos metadados.
        List<Certificado> certificados = manifest.certificados();
        List<CertificadoX509> pares = new ArrayList<>(certificados.size());
        ExpansorCertificados expansor = new ExpansorCertificados();
        try {
            for (Certificado cert : certificados) {
                byte[] der = reader.lerCertificadoDer(cert.arquivo());
                X509Certificate x509 = expansor.parsearCertificado(der, cert.arquivo());
                pares.add(new CertificadoX509(cert, x509));
            }
        } catch (RuntimeException e) {
            return abortar("persistir",
                    "Falha ao ler certificados da staging: " + mensagemConcisa(e)
                            + ". Keystore nao modificado.");
        }

        KeystoreBks keystoreBks = new KeystoreBks();

        // 3) Snapshot ANTES da gravacao.
        List<Certificado> antes;
        try {
            antes = keystoreBks.snapshot(keystore, senha);
        } catch (KeystoreBks.KeystoreException e) {
            return abortar("persistir",
                    "Falha ao ler o keystore atual em " + keystore + ": " + mensagemConcisa(e)
                            + ". Keystore nao modificado.");
        }

        // 4) Deduplicacao conforme o metodo selecionado (nunca filtra por validade - Req 6.2, 6.3).
        List<Certificado> entradaDedup = pares.stream().map(CertificadoX509::cert).toList();
        ResultadoDedup resultadoDedup = getMetodoDedup() == MetodoDedup.AGRESSIVO
                ? Deduplicador.agressivo(entradaDedup)
                : Deduplicador.conservador(entradaDedup);
        List<Certificado> mantidos = resultadoDedup.mantidos();

        // 5) Geracao de aliases unicos case-insensitive (Req 8.1, 8.5).
        List<AtribuicaoAlias> atribuicoes = GeradorAlias.gerarAliases(mantidos);

        // 6) Decisao de gravacao apos eventuais falhas de download (Req 7.2-7.5).
        int nFalhas = manifest.falhas() == null ? 0 : manifest.falhas().size();
        boolean temTty = System.console() != null;
        String resposta = null;
        if (nFalhas > 0 && temTty) {
            Console console = System.console();
            resposta = console.readLine(
                    "Houve %d falha(s) de download. Continuar mesmo assim? (s/N): ", nFalhas);
        }
        if (!DecisorGravacao.deveGravar(nFalhas, temTty, resposta)) {
            String motivo = temTty
                    ? "gravacao nao confirmada pelo operador"
                    : "sem terminal interativo para confirmar";
            return abortar("persistir", nFalhas,
                    "Gravacao abortada apos " + nFalhas + " falha(s) de download ("
                            + motivo + "). Keystore nao modificado.");
        }

        // 7) Gravacao atomica: de-para entre AtribuicaoAlias e o X509 real (Req 1.7, 10.8).
        List<KeystoreBks.EntradaKeystore> entradas = montarEntradas(atribuicoes, pares);
        try {
            keystoreBks.gravarAtomico(entradas, keystore, senha);
        } catch (KeystoreBks.KeystoreException e) {
            // Rollback ja aplicado pela KeystoreBks; NAO emitir o Relatorio_Persistencia.
            return abortar("persistir",
                    "Falha ao gravar o keystore em " + keystore + " (rollback aplicado): "
                            + mensagemConcisa(e));
        }

        // 8) Sucesso: snapshot DEPOIS, diff e Relatorio_Persistencia (Req 10.1).
        List<Certificado> depois = keystoreBks.snapshot(keystore, senha);
        DiffKeystore diff = CalculadoraDiff.calcular(antes, depois, resultadoDedup, atribuicoes);
        System.out.print(RelatorioPersistenciaBuilder.construir(diff));

        // 9) Resultado e exit code (Req 9.1, 9.2).
        ResultadoExecucao resultado = new ResultadoExecucao(
                "persistir", nFalhas,
                "Persistencia concluida: " + entradas.size() + " certificado(s) gravado(s).");
        System.out.println(DecisorExitCode.mensagemFinal(resultado));
        return DecisorExitCode.codigo(resultado);
    }

    /**
     * Monta a lista de entradas do keystore fazendo o de-para entre cada
     * {@link AtribuicaoAlias} (que carrega o {@link Certificado} de dominio e o
     * {@code aliasFinal}) e o {@link X509Certificate} real correspondente.
     */
    private static List<KeystoreBks.EntradaKeystore> montarEntradas(
            List<AtribuicaoAlias> atribuicoes, List<CertificadoX509> pares) {
        List<KeystoreBks.EntradaKeystore> entradas = new ArrayList<>(atribuicoes.size());
        for (AtribuicaoAlias atribuicao : atribuicoes) {
            X509Certificate x509 = localizarX509(atribuicao.cert(), pares);
            entradas.add(new KeystoreBks.EntradaKeystore(atribuicao.aliasFinal(), x509));
        }
        return entradas;
    }

    /**
     * Localiza o {@link X509Certificate} real associado a um {@link Certificado}
     * de dominio, comparando por identidade estavel (referencia primeiro, depois
     * {@link Certificado#identidade()}).
     */
    private static X509Certificate localizarX509(Certificado cert, List<CertificadoX509> pares) {
        for (CertificadoX509 par : pares) {
            if (par.cert() == cert || par.cert().identidade().equals(cert.identidade())) {
                return par.x509();
            }
        }
        throw new IllegalStateException(
                "Certificado sem X.509 correspondente na staging: " + cert.identidade());
    }

    /** Emite a mensagem de aborto sem falhas explicitas de download (exit != 0). */
    private static int abortar(String processo, String mensagem) {
        return abortar(processo, 1, mensagem);
    }

    /** Emite a mensagem de aborto com {@code nFalhas} e retorna o exit code correspondente. */
    private static int abortar(String processo, int nFalhas, String mensagem) {
        ResultadoExecucao resultado = new ResultadoExecucao(
                processo, Math.max(nFalhas, 1), mensagem);
        System.err.println(mensagem);
        System.err.println(DecisorExitCode.mensagemFinal(resultado));
        return DecisorExitCode.codigo(resultado);
    }

    /** Extrai uma mensagem concisa da excecao, evitando stack trace cru ao operador. */
    private static String mensagemConcisa(Throwable e) {
        String msg = e.getMessage();
        if (msg == null || msg.isBlank()) {
            Throwable causa = e.getCause();
            if (causa != null && causa.getMessage() != null) {
                return causa.getMessage();
            }
            return e.getClass().getSimpleName();
        }
        return msg;
    }

    /** Par imutavel associando o {@link Certificado} de dominio ao seu {@link X509Certificate}. */
    private record CertificadoX509(Certificado cert, X509Certificate x509) {
    }
}
