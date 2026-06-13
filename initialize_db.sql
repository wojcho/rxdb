-- For testing: `docker run --rm --name pg-test -e POSTGRES_PASSWORD=pass -p 5432:5432 -d postgres:18`
-- In PostgreSQL VSCodium extension set the following:
-- Server name: localhost
-- Port: 5432
-- User name: postgres
-- Password: pass
-- Database: postgres

\c postgres

-- =====================================================
-- Extensions
-- =====================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =====================================================
-- Security
-- =====================================================

CREATE ROLE rxdb_admin LOGIN PASSWORD 'SECRET_HERE';
CREATE ROLE rxdb_user;

-- Public schema, any users can read and insert, other operations are forbidden for them
CREATE SCHEMA IF NOT EXISTS rxdb_base;
ALTER SCHEMA rxdb_base OWNER TO rxdb_admin;

-- Private, only admin can read and insert, other opertations are forbidden for anyone
CREATE SCHEMA IF NOT EXISTS rxdb_private;
ALTER SCHEMA rxdb_private OWNER TO rxdb_admin;

-- Setting permissions is done at end of the script

-- =====================================================
-- Initializing tables
-- =====================================================

-- Object header
CREATE TABLE IF NOT EXISTS rxdb_base.object (
  object_id UUID PRIMARY KEY UNIQUE NOT NULL DEFAULT gen_random_uuid(),
  created_at TIMESTAMP NOT NULL DEFAULT now(),
  creating_user_object_id UUID NOT NULL, -- fk_object_creating_user
  CONSTRAINT fk_object_creating_user -- Here there is only seemingly a circular dependency, user has to be present to create objects, but that is why during bootstrap, admin user is created under temporarily disabled constraint, later when creating users they are created by admin
    FOREIGN KEY (creating_user_object_id)
    REFERENCES rxdb_base.object (object_id)
    ON UPDATE CASCADE
    ON DELETE RESTRICT
);

-- Version Header
CREATE TABLE IF NOT EXISTS rxdb_base.version (
  version_id VARCHAR(1024) PRIMARY KEY UNIQUE NOT NULL DEFAULT gen_random_uuid()::varchar, -- It is not just UUID, to enable users to set arbitrary version IDs for easier access, that UUID here is a fallback and should be used sparingly, TODO alternatively other random text could be used
  object_id UUID NOT NULL, -- fk_version_object
  created_at TIMESTAMP NOT NULL DEFAULT now(),
  creating_user_object_id UUID NOT NULL, -- fk_version_creating_user
  is_property BOOLEAN DEFAULT FALSE, -- Whether that version can be used in graph as an edge (TODO graph queries later)
  is_tombstone BOOLEAN DEFAULT FALSE, -- Whether that version is logically removed (usual removal is forbidden)
  CONSTRAINT fk_version_object
    FOREIGN KEY (object_id)
    REFERENCES rxdb_base.object (object_id)
    ON UPDATE CASCADE
    ON DELETE CASCADE,
  CONSTRAINT fk_version_creating_user
    FOREIGN KEY (creating_user_object_id)
    REFERENCES rxdb_base.object (object_id)
    ON UPDATE CASCADE
    ON DELETE RESTRICT
);

-- User Version Data
CREATE TABLE IF NOT EXISTS rxdb_private.user_version (
  version_id VARCHAR(1024) PRIMARY KEY NOT NULL, -- fk_user_version_version
  password_hash VARCHAR,
  CONSTRAINT fk_user_version_version
    FOREIGN KEY (version_id)
    REFERENCES rxdb_base.version (version_id)
    ON UPDATE CASCADE
    ON DELETE CASCADE
);

-- Log Version Data (similar tables also per schema)
CREATE TABLE IF NOT EXISTS rxdb_base.log_version (
  version_id VARCHAR(1024) PRIMARY KEY NOT NULL, -- fk_log_version_version
  creating_user_object_id UUID NOT NULL,
  operation JSONB,
  CONSTRAINT fk_log_version_version_rxdb_base
    FOREIGN KEY (version_id)
    REFERENCES rxdb_base.version (version_id)
    ON UPDATE CASCADE
    ON DELETE CASCADE
);

-- =====================================================
-- Procedures and Functions
-- =====================================================

-- User

-- Insert User (only admin can run)
CREATE OR REPLACE PROCEDURE rxdb_private.insert_user(
  new_username VARCHAR,
  new_password VARCHAR
)
LANGUAGE plpgsql
AS $$
BEGIN
  -- TODO create database user
  -- TODO grant them role rxdb_user
  -- TODO compute password hash
  INSERT INTO rxdb_base.object(...)
    VALUES(...)
    RETURNING object_id
    INTO new_object_id;
  INSERT INTO rxdb_base.version(
      version_id,
      object_id,
      creating_user_object_id
    )
    VALUES(
      new_username,
      new_object_id,
      'rxdb_admin'
    )
    RETURNING version_id
    INTO new_version_id;
  INSERT INTO rxdb_private.user_version(
    version_id,
    username,
    password_hashed,
    password_salt
  )
  VALUES(
    new_version_id,
    new_username,
    hashed_password,
    salt
  );
END;
$$;

-- Validate password hash, Login as user (anyone can run)
CREATE OR REPLACE FUNCTION rxdb_private.is_valid_password(
  user_username VARCHAR,
  user_password VARCHAR
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
  -- TODO SELECT password_hashed FROM rxdb_private.user_version
  -- TODO validate password hash
END;
$$;

-- Update User by Adding New Version (admin and user themselves can run)
CREATE OR REPLACE PROCEDURE rxdb_private.update_user(
  object_id UUID,
  new_username VARCHAR,
  new_password VARCHAR
)
LANGUAGE plpgsql
AS $$
BEGIN
  -- TODO
  INSERT INTO rxdb_base.version () VALUES ();
  INSERT INTO rxdb_private.user_version () VALUES ();
END;
$$;

-- Log

-- Insert Log (anyone can run)
CREATE OR REPLACE PROCEDURE rxdb_base.insert_log(
  domain_name VARCHAR,
  operation JSONB
)
LANGUAGE plpgsql
AS $$
BEGIN
  -- TODO
  INSERT INTO rxdb_base.object () VALUES ();
  INSERT INTO rxdb_base.version () VALUES ();
  INSERT INTO rxdb_base.insert_log () VALUES ();
END;
$$;

-- Domains/Schemas

-- Select List of Accessible Schemas (anyone can run, output is different for them)
-- CREATE OR REPLACE FUNCTION rxdb_base.select_accessible_schemas()
-- RETURNS JSONB
-- LANGUAGE plpgsql
-- AS $$
-- DECLARE
--   retval JSONB;
-- BEGIN
--   SELECT jsonb_agg(schema_name)
--   INTO retval
--   FROM information_schema.schemata
--   WHERE has_schema_privilege(
--     current_user,
--     schema_name,
--     'USAGE'
--   );
--   RETURN COALESCE(retval, '[]'::jsonb);
-- END;
-- $$;

-- Select Permissions in a Schema (anyone with access to schema can run)
-- CREATE OR REPLACE FUNCTION rxdb_base.select_schema_permissions(
--   domain_name VARCHAR
-- )
-- RETURNS JSONB
-- LANGUAGE plpgsql
-- AS $$
-- DECLARE
--   retval JSONB;
-- BEGIN
--   SELECT jsonb_agg(privilege_type)
--   INTO retval
--   FROM information_schema.role_schema_grants
--   WHERE grantee = current_user
--     AND schema_name = p_schema;
--   RETURN COALESCE(retval, '[]'::jsonb);
-- END;
-- $$;

-- Create Custom Domain/Schema (Schema and Log Table) (anoyone can run)
-- CREATE OR REPLACE PROCEDURE rxdb_base.create_domain (
--   domain_name VARCHAR,
--   schema_permissions JSONB
-- )
-- LANGUAGE plpgsql
-- AS $$
-- BEGIN
--   -- TODO parse schema_permissions
--   EXECUTE format(
--     'CREATE SCHEMA IF NOT EXISTS %I',
--     domain_name
--   );
--   EXECUTE format(
--     '
--     CREATE TABLE IF NOT EXISTS %I.log_version (
--       version_id VARCHAR(1024) PRIMARY KEY,
--       creating_user_object_id UUID NOT NULL,
--       operation JSONB,
--       CONSTRAINT fk_log_version_version_%I
--         FOREIGN KEY (version_id)
--         REFERENCES rxdb_base.version (version_id)
--         ON UPDATE CASCADE
--         ON DELETE CASCADE
--     )', -- TODO fk_log_version_version_ avoid SQL injection without potential '' mid-name which could cause errors
--     domain_name
--   );
--   CALL rxdb_base.update_domain_permissions(
--     domain_name,
--     schema_permissions
--   );
-- END;
-- $$;

-- Update Custom Domain/Schema Permissions (anyone with schema permission editing permission can run)
-- CREATE OR REPLACE PROCEDURE rxdb_base.update_domain_permissions (
--   domain_name VARCHAR,
--   schema_permissions JSONB
-- )
-- LANGUAGE plpgsql
-- AS $$
-- BEGIN
--   -- TODO
--   -- revoke all permissions
--   -- grant new permissions
-- END;
-- $$;

-- Tables/Types

-- Select List of All Tables in Schema (anyone with access to schema can run)
-- CREATE OR REPLACE FUNCTION rxdb_base.select_table_names_in_schema(
--   domain_name VARCHAR
-- )
-- RETURNS JSONB
-- LANGUAGE plpgsql
-- AS $$
-- DECLARE
--   retval JSONB;
-- BEGIN
--   SELECT jsonb_agg(table_name)
--   INTO retval
--   FROM information_schema.tables
--   WHERE table_schema = domain_name
--     AND table_type = 'BASE TABLE';
--   RETURN COALESCE(retval, '[]'::jsonb);
-- END;
-- $$;

-- Select Type/Table Definition (anyone with access to schema can run)
-- CREATE OR REPLACE FUNCTION rxdb_base.select_table_definition(
--   domain_name VARCHAR,
--   type_name VARCHAR
-- )
-- RETURNS JSONB
-- LANGUAGE plpgsql
-- AS $$
-- DECLARE
--   retval JSONB;
-- BEGIN
--   -- TODO select information about indices, foreign keys
--   SELECT jsonb_agg(
--     jsonb_build_object(
--       'column_name', column_name,
--       'data_type', data_type,
--       'nullable', is_nullable,
--       'default', column_default
--     )
--   )
--   INTO retval
--   FROM information_schema.columns
--   WHERE table_schema = domain_name
--     AND table_name = type_name;
--   RETURN COALESCE(retval, '[]'::jsonb);
-- END;
-- $$;

-- Create Custom Type/Table (anyone with access to schema can run)
-- CREATE OR REPLACE PROCEDURE rxdb_base.create_type(
--   domain_name VARCHAR,
--   type_name VARCHAR,
--   table_definition JSONB -- as returned by table_definition
-- )
-- LANGUAGE plpgsql
-- AS $$
-- BEGIN
--   -- TODO
--   CREATE TABLE domain_name.type_name ();
--   -- TODO later after getting it to work, it could also create a function view with joined rxdb_base.object, rxdb_base.version, domain_name.type_name to show latest versions, but that is for later
-- END;
-- $$;

-- =====================================================
-- Restrict Security
-- =====================================================

-- Public schema, any users can read and insert, other operations are forbidden for them
REVOKE ALL ON SCHEMA rxdb_base FROM PUBLIC;
GRANT USAGE ON SCHEMA rxdb_base TO PUBLIC;

-- Tables

GRANT SELECT, INSERT
ON ALL TABLES IN SCHEMA rxdb_base
TO PUBLIC;

REVOKE UPDATE, DELETE, TRUNCATE
ON ALL TABLES IN SCHEMA rxdb_base
FROM PUBLIC;

ALTER DEFAULT PRIVILEGES
FOR ROLE rxdb_admin
IN SCHEMA rxdb_base
GRANT SELECT, INSERT ON TABLES TO PUBLIC;

ALTER DEFAULT PRIVILEGES
FOR ROLE rxdb_admin
IN SCHEMA rxdb_base
REVOKE UPDATE, DELETE, TRUNCATE ON TABLES FROM PUBLIC;

-- Private, only admin can read and insert, other opertations are forbidden for anyone
REVOKE ALL ON SCHEMA rxdb_private FROM PUBLIC;
GRANT USAGE ON SCHEMA rxdb_private TO rxdb_admin;

-- Tables

GRANT ALL
ON ALL TABLES IN SCHEMA rxdb_private
TO rxdb_admin;

REVOKE ALL
ON ALL TABLES IN SCHEMA rxdb_private
FROM PUBLIC;

ALTER DEFAULT PRIVILEGES
FOR ROLE rxdb_admin
IN SCHEMA rxdb_private
GRANT ALL ON TABLES TO rxdb_admin;

ALTER DEFAULT PRIVILEGES
FOR ROLE rxdb_admin
IN SCHEMA rxdb_private
REVOKE ALL ON TABLES FROM PUBLIC;

-- Procedures

REVOKE ALL
ON PROCEDURE rxdb_private.create_user
FROM PUBLIC;

GRANT EXECUTE
ON PROCEDURE rxdb_private.create_user
TO rxdb_admin;

-- Any user can create their own schemas, where they can do anything
GRANT CREATE ON DATABASE postgres TO PUBLIC;

-- =====================================================
-- Initialization
-- =====================================================

-- Create first user, rxdb_admin
-- TODO
-- remove constraint fk_object_creating_user on rxdb_base.object
-- CALL rxdb_private.create_user()
-- readd constraint fk_object_creating_user on rxdb_base.object

-- =====================================================
-- Custom Schemas, Tables, Versions
-- =====================================================
-- TODO
