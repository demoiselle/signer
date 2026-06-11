package main

import (
	"fmt"
	"os"
	"os/exec"
)

func main() {
	fmt.Println("=== Iniciando execução de testes multi-versão ===")
	
	// Versões baseadas nos candidatos disponíveis via SDKMAN (Temurin) no ambiente atual
	versions := []string{
		"8.0.492-tem",
		"11.0.31-tem",
		"17.0.19-tem",
		"25.0.3-tem",
	}

	allPassed := true

	for _, version := range versions {
		fmt.Printf("\n------------------------------------------------------------\n")
		fmt.Printf("➜ Rodando testes para Java %s\n", version)
		fmt.Printf("------------------------------------------------------------\n")

		// Comando executa o ambiente SDKMAN, ativa a versão do loop, e roda o maven
		// Estamos limitando ao modulo "core" (-pl core) pois é onde as implementações recentes estão,
		// e pulamos logs excessivos (-q e -B para batch mode)
		cmdStr := fmt.Sprintf(`source "$HOME/.sdkman/bin/sdkman-init.sh" && sdk use java %s && mvn clean test -pl core -B`, version)
		
		cmd := exec.Command("bash", "-c", cmdStr)
		
		// Conecta o processo filho as saídas padrão do Go para vermos o log em tempo real
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		err := cmd.Run()
		
		if err != nil {
			fmt.Printf("❌ Falha nos testes para o Java %s\n", version)
			allPassed = false
		} else {
			fmt.Printf("✅ Sucesso nos testes para o Java %s\n", version)
		}
	}

	fmt.Println("\n=== Resumo ===")
	if allPassed {
		fmt.Println("✅ TODOS OS TESTES PASSARAM em todas as versões do Java!")
		os.Exit(0)
	} else {
		fmt.Println("❌ HOUVERAM FALHAS em uma ou mais versões do Java.")
		os.Exit(1)
	}
}
