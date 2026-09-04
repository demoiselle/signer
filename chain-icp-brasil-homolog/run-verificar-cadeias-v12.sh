#!/bin/bash
# Script para executar o Verificador de Cadeias v12
# Uso: ./run-verificar-cadeias-v12.sh
# Requer: Java 11+, Maven, acesso a rede SERPRO (VPN)

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIGNER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$SIGNER_DIR"

# Compila se necessario
if [ ! -f "chain-icp-brasil-homolog/target/classes/org/demoiselle/signer/chain/icp/brasil/provider/hom/VerificarCadeiasV12.class" ]; then
    echo "Compilando..."
    mvn compile -pl chain-icp-brasil-homolog -q
fi

# Monta classpath
CP_DEPS=$(mvn dependency:build-classpath -pl chain-icp-brasil-homolog -q -DincludeScope=compile -Dmdep.outputFile=/dev/stdout 2>/dev/null)
CP="chain-icp-brasil-homolog/target/classes:$CP_DEPS"

echo "Executando Verificador de Cadeias v12..."
java -cp "$CP" org.demoiselle.signer.chain.icp.brasil.provider.hom.VerificarCadeiasV12 "$@"
