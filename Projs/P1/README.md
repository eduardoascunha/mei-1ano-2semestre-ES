
# Secure Vault

## Relatório

Os elementos do relatório encontram-se no diretório **"relatório"**, divididos em 3 fases:

- **Ameaças e Análise de Risco**: `Análise.pdf`
- **Requisitos**: `Requisitos.pdf`
- **Desenho da Solução e Prototipagem**: `Solução.pdf`

## Execução do Protótipo
Para executar o protótipo, além do código fornecido, é necessário criar um ficheiro *.env* com a definição das variáveis de ambiente associadas à base de dados (nome da base de dados, nome de utilizador, palavra-passe do administrador, e host). Deve ainda ser definido o caminho e a palavra-passe para o ficheiro de logs, garantindo o correto funcionamento da aplicação.

### Base de Dados

No diretório **"database"** encontram-se scripts para a inicialização e remoção da base de dados (caso deseje utilizar).

- **Inicialização**: `setup_cofre.sql`
- **Remoção**: `drop_cofre.sql`

### Execução do Programa

Fluxo para a execução do protótipo:

1. **Gerar Certificados**: Executar o script `gerar_certificados.py` para gerar os certificados necessários.
2. **Iniciar o Servidor**: Executar o script `servidor.py` para iniciar o servidor.
3. **Iniciar o(s) Cliente(s)**: Executar o script `cliente.py` para iniciar o(s) cliente(s).
