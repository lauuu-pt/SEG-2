#!/bin/bash

# Verifica se o nome de usuário foi fornecido como argumento
if [ $# -ne 1 ]; then
    echo "Uso: $0 <nome do usuário>"
    exit 1
fi

echo "Passo 1: Argumento fornecido corretamente."

# Nome do arquivo da keystore
keystore_file="keystore.$1"

echo "Passo 2: Nome do arquivo da keystore definido: $keystore_file"

# Extrai a senha da keystore usando openssl
keystore_password=$(openssl pkcs12 -info -in "$keystore_file" -noout -passin pass: 2>&1 | awk '/MAC:/ {getline; print}')

echo "Passo 3: Senha da keystore obtida."

# Exibe a senha armazenada na variável
echo "A senha da keystore é: $keystore_password"

