-- Criar a base de dados se não existir
DROP DATABASE IF EXISTS cofredigital;
CREATE DATABASE cofredigital;

-- Conectar ao banco de dados
\connect cofredigital;

-- Criar usuário admin
DROP ROLE IF EXISTS adminES;
CREATE USER adminES WITH PASSWORD 'adminES2025_'; -- # mt mais seguro q admin xd

-- Conceder privilégios ao usuário admin
GRANT ALL PRIVILEGES ON DATABASE cofredigital TO adminES;
GRANT ALL ON SCHEMA public TO adminES;
GRANT CREATE ON SCHEMA public TO adminES;   
GRANT ALL ON ALL TABLES IN SCHEMA public TO adminES;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO adminES;
ALTER USER adminES WITH SUPERUSER;

-- Dropar tabelas existentes para recriação
DROP TABLE IF EXISTS permissoes CASCADE;
DROP TABLE IF EXISTS chaves CASCADE;
DROP TABLE IF EXISTS arquivos CASCADE;
DROP TABLE IF EXISTS pastas CASCADE;
DROP TABLE IF EXISTS cofres CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- Criar enum para tipos de permissão
DROP TYPE IF EXISTS nivel_acesso CASCADE;
CREATE TYPE nivel_acesso AS ENUM ('read', 'append', 'write');

-- Criar tabelas
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    senha_hash VARCHAR(255) NOT NULL,
    certificado TEXT NOT NULL,
    data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    two_fa_ativado BOOLEAN DEFAULT FALSE,
    two_fa_secret VARCHAR(32),
    google_user_id VARCHAR(255),
    google_access_token VARCHAR(255),
    google_refresh_token VARCHAR(255),
    CONSTRAINT email_valido CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
);

CREATE TABLE cofres (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    dono_id UUID UNIQUE NOT NULL,
    data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (dono_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE pastas (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nome VARCHAR(255) NOT NULL,
    cofre_id UUID NOT NULL,
    pasta_pai_id UUID,
    data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (cofre_id) REFERENCES cofres(id) ON DELETE CASCADE,
    FOREIGN KEY (pasta_pai_id) REFERENCES pastas(id) ON DELETE CASCADE,
    UNIQUE (nome, cofre_id, pasta_pai_id)
);

CREATE TABLE ficheiros (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nome VARCHAR(255) NOT NULL,
    cofre_id UUID NOT NULL,
    pasta_id UUID,
    conteudo TEXT NOT NULL,
    iv TEXT NOT NULL,
    tag TEXT NOT NULL,        
    tipo VARCHAR(50) NOT NULL,
    tamanho BIGINT NOT NULL,
    data_upload TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    hash_verificacao TEXT ,
    FOREIGN KEY (cofre_id) REFERENCES cofres(id) ON DELETE CASCADE,
    FOREIGN KEY (pasta_id) REFERENCES pastas(id) ON DELETE CASCADE,
    UNIQUE (nome, cofre_id, pasta_id)
);

CREATE TABLE permissoes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    recurso_id UUID NOT NULL,  
    tipo_recurso VARCHAR(10) NOT NULL CHECK (tipo_recurso IN ('ficheiro', 'pasta')),
    nivel nivel_acesso NOT NULL,
    data_concessao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (user_id, recurso_id)
);

CREATE TABLE chaves (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ficheiro_id UUID NOT NULL,
    user_id UUID NOT NULL,
    chave_cifrada TEXT NOT NULL,
    data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ficheiro_id) REFERENCES ficheiros(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (ficheiro_id, user_id)
);

-- Transferir propriedade das tabelas para o admin
ALTER TABLE users OWNER TO adminES;
ALTER TABLE cofres OWNER TO adminES;    
ALTER TABLE pastas OWNER TO adminES;
ALTER TABLE ficheiros OWNER TO adminES;
ALTER TABLE permissoes OWNER TO adminES;
ALTER TABLE chaves OWNER TO adminES;

-- Transferir propriedade do enum para admin
ALTER TYPE nivel_acesso OWNER TO adminES;

SELECT 'Base de dados configurado com sucesso!' AS status;

-- sudo -u postgres psql -f bd/setup_cofre.sql
