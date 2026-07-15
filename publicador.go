package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Lista de módulos na ordem recomendada de publicação
var modules = []string{
	"bom",
	"parent",
	"core",
	"cryptography",
	"chain-icp-brasil",
	"chain-icp-brasil-homolog",
	"chain-iti",
	"chain-iti-homolog",
	"chain-serpro-neosigner",
	"policy-engine",
	"policy-impl-cades",
	"policy-impl-pades",
	"policy-impl-xades",
	"signer-xmldsig",
	"timestamp",
}

func main() {
	start := time.Now()
	fmt.Println("🚀 Iniciando publicação módulo a módulo da versão 4.6.1...")

	wd, err := os.Getwd()
	if err != nil {
		fmt.Printf("❌ Erro ao obter diretório atual: %v\n", err)
		os.Exit(1)
	}

	successCount := 0
	failCount := 0
	var failedModules []string

	for _, mod := range modules {
		fmt.Printf("\n📦 Processando módulo: [%s]\n", mod)
		modPath := filepath.Join(wd, mod)

		if _, err := os.Stat(modPath); os.IsNotExist(err) {
			fmt.Printf("⚠️  Aviso: Diretório %s não encontrado, pulando...\n", mod)
			continue
		}

		cmd := exec.Command("mvn", "clean", "deploy", "-DskipTests", "-B")
		cmd.Dir = modPath
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		err := cmd.Run()
		if err != nil {
			fmt.Printf("❌ Erro ao publicar módulo %s: %v\n", mod, err)
			failCount++
			failedModules = append(failedModules, mod)
		} else {
			fmt.Printf("✅ Módulo %s publicado com sucesso!\n", mod)
			successCount++
		}
	}

	duration := time.Since(start)
	fmt.Println("\n" + filepath.Repeat("-", 40))
	fmt.Printf("🏁 Finalizado em %v\n", duration.Truncate(time.Second))
	fmt.Printf("📊 Resumo: %d Sucessos, %d Falhas\n", successCount, failCount)

	if failCount > 0 {
		fmt.Printf("❌ Módulos com erro: %v\n", failedModules)
		os.Exit(1)
	}

	fmt.Println("✨ Todos os módulos foram processados!")
}
