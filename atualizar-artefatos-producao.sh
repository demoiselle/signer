#!/bin/bash

# Script de Automação Total para Atualização de Cadeias e Políticas (PRODUÇÃO)
# Este script executa o download das políticas, o download das cadeias de certificados,
# a geração do keystore BKS e move os artefatos para as pastas de recursos do projeto.

set -e # Para em caso de erro

echo "================================================================"
echo "Iniciando Atualização de Artefatos de Produção (ICP-Brasil)"
echo "================================================================"

# 1. Atualizar Políticas
echo ""
echo "[1/3] Atualizando Políticas de Assinatura..."
cd policy-engine/automacao-atualizacao
go run 02-baixar-politicas.go
cd ../..

# 2. Atualizar Cadeias de Certificados
echo ""
echo "[2/3] Baixando Cadeias de Certificados da ICP-Brasil..."
cd chain-icp-brasil/src/scripts_keytool
go run 01-baixar-cadeias.go

echo ""
echo "[3/3] Gerando Keystore BKS..."
# Certifique-se de que o bcprov-jdk15on-1.65.jar está na pasta
go run importar-certificados.go

# 3. Mover Keystore para Resources
echo ""
echo "Movendo cadeiasicpbrasil.bks para resources..."
cp cadeiasicpbrasil.bks ../main/resources/cadeiasicpbrasil.bks

cd ../../../

echo ""
echo "================================================================"
echo "ATUALIZAÇÃO CONCLUÍDA COM SUCESSO!"
echo "================================================================"
echo "Próximos passos recomendados:"
echo "1. Execute 'mvn clean install -DskipTests' para buildar com os novos artefatos."
echo "2. Execute os testes de integração para validar a compatibilidade: 'mvn verify -Pit'"
echo "================================================================"
