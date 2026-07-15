#!/bin/bash

# Script de Automação Total para Atualização de Cadeias e Políticas (HOMOLOGAÇÃO)
# Este script executa o download das políticas, o download das cadeias de homologação,
# a geração do keystore BKS e move os artefatos para as pastas de recursos do projeto.

set -e # Para em caso de erro

echo "================================================================"
echo "Iniciando Atualização de Artefatos de Homologação (Serpro/ICP-Brasil)"
echo "================================================================"

# 1. Atualizar Políticas (Compartilhadas entre Prod/Homolog)
echo ""
echo "[1/2] Atualizando Políticas de Assinatura..."
cd policy-engine/automacao-atualizacao
go run 02-baixar-politicas.go
cd ../..

# 2. Atualizar Cadeias de Certificados de Homologação
echo ""
echo "[2/2] Processando Cadeias de Homologação (Download e Keystore BKS)..."
cd chain-icp-brasil-homolog
go run atualizar-homologacao.go

# 3. Mover Keystore para Resources
echo ""
echo "Movendo cadeiasicpbrasil-HOMOLOGACAO.bks para resources..."
cp cadeiasicpbrasil-HOMOLOGACAO.bks src/main/resources/cadeiasicpbrasil-HOMOLOGACAO.bks

cd ../

echo ""
echo "================================================================"
echo "ATUALIZAÇÃO DE HOMOLOGAÇÃO CONCLUÍDA COM SUCESSO!"
echo "================================================================"
echo "Próximos passos recomendados:"
echo "1. Execute 'mvn clean install -DskipTests' para buildar com os novos artefatos."
echo "2. Execute os testes de homologação: 'go run run-all-lts-tests.go'"
echo "================================================================"
