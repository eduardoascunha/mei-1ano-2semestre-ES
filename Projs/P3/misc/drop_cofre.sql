-- Desconectar todos os users antes de excluir a bd
SELECT pg_terminate_backend(pg_stat_activity.pid)
FROM pg_stat_activity
WHERE pg_stat_activity.datname = 'cofredigital';

-- Apagar a bd se existir
DROP DATABASE IF EXISTS cofredigital;

-- Remover o user admin se existir
DROP ROLE IF EXISTS adminEC;

-- Retornar mensagem de status
SELECT 'Base de dados "cofredigital" excluído com sucesso!' AS status;
SELECT 'User "adminEC" excluído com sucesso!' AS status;


-- sudo -u postgres psql -f bd/drop_cofre.sql
