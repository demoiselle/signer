package org.demoiselle.signer.importador.cli;

import java.io.PrintWriter;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import picocli.CommandLine;
import picocli.CommandLine.IExecutionExceptionHandler;
import picocli.CommandLine.ParseResult;

/**
 * Ponto de entrada da aplicacao autonoma ({@code Main-Class} do uber-jar).
 *
 * <p>Responsabilidades:</p>
 * <ol>
 *   <li>Registrar o provider BouncyCastle de forma <strong>idempotente</strong>
 *       ({@code Security.addProvider(new BouncyCastleProvider())} somente se ainda
 *       nao registrado), garantindo que {@code KeyStore.getInstance("BKS","BC")},
 *       {@code CMSSignedData} e {@code CertificateFactory} estejam disponiveis;</li>
 *   <li>Construir o {@link CommandLine} sobre {@link ImportadorCli} e executar os
 *       argumentos: {@code int exit = commandLine.execute(args)};</li>
 *   <li>Propagar o resultado como exit code do processo via {@link System#exit(int)}.</li>
 * </ol>
 *
 * <p>Como {@link ComandoBaixar} e {@link ComandoPersistir} retornam um {@code Integer}
 * (exit code derivado de {@code DecisorExitCode}) do seu {@code call()}, o picocli
 * propaga esse valor como codigo de retorno de {@link CommandLine#execute(String...)},
 * de modo que o exit code do processo reflita o resultado (0 sucesso, != 0 falha)
 * (Req 9.1, 9.2).</p>
 *
 * <p>Requisitos atendidos: 1.1, 9.1, 9.2.</p>
 */
public final class Main {

    /** Nome do provider BouncyCastle registrado no {@link Security}. */
    private static final String PROVIDER_BC = "BC";

    private Main() {
    }

    /**
     * Ponto de entrada do processo.
     *
     * @param args argumentos da linha de comando (subcomando + opcoes)
     */
    public static void main(String[] args) {
        registrarProviderBouncyCastle();

        int exit = novoCommandLine().execute(args);
        System.exit(exit);
    }

    /**
     * Registra o provider BouncyCastle de forma idempotente: so adiciona se ainda
     * nao houver um provider {@code BC} registrado.
     */
    static void registrarProviderBouncyCastle() {
        if (Security.getProvider(PROVIDER_BC) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Constroi o {@link CommandLine} sobre o comando raiz {@link ImportadorCli},
     * configurado para uso robusto em pipeline:
     * <ul>
     *   <li>valores de enum insensiveis a maiusculas/minusculas;</li>
     *   <li>um {@link IExecutionExceptionHandler} simples que imprime mensagens
     *       concisas de excecao (sem stack trace cru) e retorna um exit code != 0.</li>
     * </ul>
     *
     * @return o {@link CommandLine} pronto para {@link CommandLine#execute(String...)}
     */
    static CommandLine novoCommandLine() {
        return new CommandLine(new ImportadorCli())
                .setCaseInsensitiveEnumValuesAllowed(true)
                .setExecutionExceptionHandler(new HandlerExcecaoConciso());
    }

    /**
     * Handler de excecao de execucao que imprime uma mensagem concisa no
     * {@code stderr} (sem stack trace cru para o operador) e retorna um exit code
     * diferente de zero, mantendo a semantica de falha (Req 9.1, 9.2).
     */
    static final class HandlerExcecaoConciso implements IExecutionExceptionHandler {
        @Override
        public int handleExecutionException(Exception ex, CommandLine commandLine, ParseResult parseResult) {
            PrintWriter err = commandLine.getErr();
            String msg = ex.getMessage();
            err.println(commandLine.getColorScheme().errorText(
                    "Erro: " + (msg == null || msg.isBlank() ? ex.getClass().getSimpleName() : msg)));
            int codigo = commandLine.getExitCodeExceptionMapper() != null
                    ? commandLine.getExitCodeExceptionMapper().getExitCode(ex)
                    : commandLine.getCommandSpec().exitCodeOnExecutionException();
            return codigo == 0 ? CommandLine.ExitCode.SOFTWARE : codigo;
        }
    }
}
