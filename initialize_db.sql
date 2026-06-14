-- For testing: `sudo docker rm -f pg-test && sudo docker run --rm --name pg-test -e POSTGRES_PASSWORD=pass -p 5432:5432 -d postgres:18`
-- In PostgreSQL VSCodium extension set the following:
-- Server name: localhost
-- Port: 5432
-- User name: postgres
-- Password: pass
-- Database: postgres

-- =====================================================
-- Extensions
-- =====================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =====================================================
-- Security
-- =====================================================

DO
$do$
BEGIN
  IF EXISTS (
    SELECT FROM pg_catalog.pg_roles
    WHERE rolname = 'rxdb_admin') THEN

    RAISE NOTICE 'Role "rxdb_admin" already exists. Skipping.';
  ELSE
    CREATE ROLE rxdb_admin LOGIN PASSWORD 'SECRET_HERE';
  END IF;
END
$do$;

DO
$do$
BEGIN
  IF EXISTS (
    SELECT FROM pg_catalog.pg_roles
    WHERE rolname = 'rxdb_user') THEN

    RAISE NOTICE 'Role "rxdb_user" already exists. Skipping.';
  ELSE
    CREATE ROLE rxdb_user LOGIN PASSWORD 'SECRET_HERE';
  END IF;
END
$do$;

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
    ON UPDATE RESTRICT -- UPDATE, DELETE are anyway forbidden
    ON DELETE RESTRICT
);

-- Version Header
CREATE TABLE IF NOT EXISTS rxdb_base.version (
  version_id VARCHAR(1024) PRIMARY KEY UNIQUE NOT NULL DEFAULT gen_random_uuid()::varchar, -- It is not just UUID, to enable users to set arbitrary version IDs for easier access (weird artifact of that decision is that name clases can be also with old versions, and because of it serving as username, once someone changes their password they also have at once to change their username), that UUID here is a fallback and should be used sparingly
  object_id UUID NOT NULL, -- fk_version_object
  created_at TIMESTAMP NOT NULL DEFAULT now(),
  creating_user_object_id UUID NOT NULL, -- fk_version_creating_user
  is_property BOOLEAN DEFAULT FALSE, -- Whether that version can be used in graph as an edge (TODO graph queries later)
  is_tombstone BOOLEAN DEFAULT FALSE, -- Whether that version is logically removed (usual removal is forbidden)
  CONSTRAINT fk_version_object
    FOREIGN KEY (object_id)
    REFERENCES rxdb_base.object (object_id)
    ON UPDATE RESTRICT -- UPDATE, DELETE are anyway forbidden
    ON DELETE RESTRICT,
  CONSTRAINT fk_version_creating_user
    FOREIGN KEY (creating_user_object_id)
    REFERENCES rxdb_base.object (object_id)
    ON UPDATE RESTRICT -- UPDATE, DELETE are anyway forbidden
    ON DELETE RESTRICT
);

-- User Version Data
CREATE TABLE IF NOT EXISTS rxdb_private.user_version (
  version_id VARCHAR(1024) PRIMARY KEY NOT NULL, -- fk_user_version_version version_id is used as username
  password_hashed VARCHAR,
  CONSTRAINT fk_user_version_version
    FOREIGN KEY (version_id)
    REFERENCES rxdb_base.version (version_id)
    ON UPDATE RESTRICT -- UPDATE, DELETE are anyway forbidden
    ON DELETE RESTRICT
);

-- Log Version Data (similar tables also per schema)
CREATE TABLE IF NOT EXISTS rxdb_base.log_version (
  version_id VARCHAR(1024) PRIMARY KEY NOT NULL, -- fk_log_version_version
  operation JSONB,
  CONSTRAINT fk_log_version_version_rxdb_base
    FOREIGN KEY (version_id)
    REFERENCES rxdb_base.version (version_id)
    ON UPDATE RESTRICT -- UPDATE, DELETE are anyway forbidden
    ON DELETE RESTRICT
);

-- =====================================================
-- Procedures and Functions
-- =====================================================

-- User

-- Select Object UUID of Current User, because Postgres uses one user per session (anyone can run)
CREATE OR REPLACE FUNCTION rxdb_base.current_user_object_id()
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  retval UUID;
BEGIN
  SELECT v.object_id
  INTO retval
  FROM rxdb_base.version v
  JOIN rxdb_private.user_version uv
    ON uv.version_id = v.version_id
  WHERE uv.version_id = current_user -- https://www.postgresql.org/docs/current/functions-info.html
  ORDER BY v.created_at DESC
  LIMIT 1;

  IF retval IS NULL THEN
    RAISE EXCEPTION
      'Current database user "%" is not recognized in RXDB',
      current_user;
  END IF;

  RETURN retval;
END;
$$;

-- Insert User (only admin can run)
CREATE OR REPLACE PROCEDURE rxdb_private.insert_user(
  new_username VARCHAR,
  new_password VARCHAR
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  new_object_id UUID;
  new_password_hashed VARCHAR;
  current_creating_user_object_id UUID;
BEGIN
  new_password_hashed := crypt(new_password, gen_salt('bf'));
  current_creating_user_object_id := rxdb_base.current_user_object_id();
  EXECUTE format(
    'CREATE USER %I LOGIN PASSWORD %L',
    new_username,
    new_password
  );
  EXECUTE format(
    'GRANT rxdb_user TO %I',
    new_username
  );
  INSERT INTO rxdb_base.object(
    creating_user_object_id
  ) VALUES (
    current_creating_user_object_id -- This would normally be run only after creating admin user, this should usually be UUID of admin, as that procedure is in rxdb_private
  ) RETURNING object_id
    INTO new_object_id;
  INSERT INTO rxdb_base.version( -- TODO Functionality from here is similar to rxdb_private.update_user, seemingly going against DRY, but that function has also change of password rather than database user creation
    version_id,
    object_id,
    creating_user_object_id
  ) VALUES (
    new_username,
    new_object_id,
    current_creating_user_object_id
  );
  INSERT INTO rxdb_private.user_version(
    version_id,
    password_hashed
  ) VALUES (
    new_username,
    new_password_hashed
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
DECLARE
  stored_hash TEXT;
BEGIN
  SELECT uv.password_hash
  INTO stored_hash
  FROM rxdb_private.user_version uv
  WHERE uv.version_id = user_username;

  IF stored_hash IS NULL THEN
    RETURN FALSE;
  END IF;

  RETURN crypt(user_password, stored_hash) = stored_hash;
END;
$$;

-- Update User by Adding New Version (admin and user themselves can run)
CREATE OR REPLACE PROCEDURE rxdb_private.update_user(
  target_object_id UUID,
  new_username VARCHAR,
  new_password VARCHAR
)
LANGUAGE plpgsql
AS $$
DECLARE
  new_password_hashed VARCHAR;
  current_creating_user_object_id UUID;
BEGIN
  new_password_hashed := crypt(new_password, gen_salt('bf'));
  current_creating_user_object_id := rxdb_base.current_user_object_id();
  INSERT INTO rxdb_base.version(
    version_id,
    object_id,
    creating_user_object_id
  ) VALUES(
    new_username,
    target_object_id,
    current_creating_user_object_id
  );
  INSERT INTO rxdb_private.user_version(
    version_id,
    password_hashed
  ) VALUES(
    new_username,
    new_username
  );
  EXECUTE format(
    'ALTER ROLE %I PASSWORD %L',
    new_username,
    new_password_hashed
  );
END;
$$;

-- Log

-- Insert Log (anyone can run)
CREATE OR REPLACE PROCEDURE rxdb_base.insert_log(
  domain_name VARCHAR,
  new_operation JSONB
)
LANGUAGE plpgsql
AS $$
DECLARE
  new_object_id UUID;
  current_creating_user_object_id UUID;
BEGIN
  current_creating_user_object_id := rxdb_base.current_user_object_id();
  INSERT INTO rxdb_base.object(
    creating_user_object_id
  ) VALUES (
    current_creating_user_object_id
  ) RETURNING object_id
    INTO new_object_id;
  INSERT INTO rxdb_base.version(
    object_id,
    creating_user_object_id
  ) VALUES(
    new_object_id,
    current_creating_user_object_id
  );
  INSERT INTO domain_name.log_version (
    operation
  ) VALUES (
    new_operation
  );
END;
$$;

-- Domains/Schemas

-- Select List of Accessible Schemas (anyone can run, output is different for them)
CREATE OR REPLACE FUNCTION rxdb_base.select_accessible_schemas()
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
  retval JSONB;
BEGIN
  SELECT jsonb_agg(schema_name)
  INTO retval
  FROM information_schema.schemata
  WHERE has_schema_privilege(
    current_user,
    schema_name,
    'USAGE'
  ) AND schema_name NOT IN ('public','information_schema')
    AND schema_name NOT LIKE 'pg_%';
  RETURN COALESCE(retval, '[]'::jsonb);
END;
$$;

-- Helper functions for Select Permissions in a Schema

CREATE OR REPLACE FUNCTION rxdb_base.acl_to_json(
  acl aclitem[]
)
RETURNS jsonb
LANGUAGE sql
STABLE
AS $$
  SELECT COALESCE(
    jsonb_agg(
      jsonb_build_object(
        'grantor',
          COALESCE(grantor_role.rolname, x.grantor::text),
        'grantee',
          CASE
            WHEN x.grantee = 0 THEN 'PUBLIC'
            ELSE grantee_role.rolname
          END,
        'privilege', x.privilege_type,
        'grantable', x.is_grantable
      )
    ),
    '[]'::jsonb
  )
  FROM aclexplode(acl) x
  LEFT JOIN pg_roles grantor_role
    ON grantor_role.oid = x.grantor
  LEFT JOIN pg_roles grantee_role
    ON grantee_role.oid = x.grantee;
$$;

-- Select Permissions in a Schema, used for reflection purposes (anyone with access to schema can run)
CREATE OR REPLACE FUNCTION rxdb_base.select_schema_permissions(
  schema_name varchar
)
RETURNS jsonb
LANGUAGE plpgsql
AS $$
DECLARE
  schema_oid oid;
  retval jsonb;
BEGIN
  SELECT oid
  INTO schema_oid
  FROM pg_namespace
  WHERE nspname = schema_name;

  IF schema_oid IS NULL THEN
    RAISE EXCEPTION
      'Schema "%" does not exist',
      schema_name;
  END IF;

  SELECT jsonb_build_object(
    'schema',
    jsonb_build_object(
      'name', n.nspname,
      'acl', rxdb_base.acl_to_json(n.nspacl)
    )
  )
  INTO retval
  FROM pg_namespace n
  WHERE n.oid = schema_oid;

  RETURN retval;
END;
$$;

SELECT rxdb_base.select_schema_permissions('rxdb_base');

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
--       operation JSONB,
--       CONSTRAINT fk_log_version_version_%I
--         FOREIGN KEY (version_id)
--         REFERENCES rxdb_base.version (version_id)
--         ON UPDATE RESTRICT -- UPDATE, DELETE are anyway forbidden
--         ON DELETE RESTRICT
--     )',
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

-- Insert into Custom Type/Table (anyone with insert access to that table can run)
-- CREATE OR REPLACE PROCEDURE rxdb_base.insert_custom(
--   domain_name VARCHAR,
--   type_name VARCHAR,
--   new_data JSONB
-- )
-- LANGUAGE plpgsql
-- AS $$
-- BEGIN
--   -- TODO
--   INSERT INTO rxdb_base.object () VALUES ();
--   INSERT INTO rxdb_base.version () VALUES ();
--   -- use EXECUTE with %I
--   INSERT INTO domain_name.type_name () VALUES ();
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
ON PROCEDURE rxdb_private.insert_user
FROM PUBLIC;

GRANT EXECUTE
ON PROCEDURE rxdb_private.insert_user
TO rxdb_admin;

-- Any user can create their own schemas, where they can do anything
GRANT CREATE ON DATABASE postgres TO PUBLIC;

-- =====================================================
-- Initialization
-- =====================================================

-- Create first user, rxdb_admin
-- TODO
-- remove constraint fk_object_creating_user on rxdb_base.object, fk_version_creating_user on rxdb_base.version
-- do what is usually done in rxdb_private.create_user(), but set user object uuid as '00000000-0000-0000-0000-000000000000'
-- readd constraint fk_object_creating_user on rxdb_base.object, fk_version_creating_user on rxdb_base.version

-- =====================================================
-- Custom Schemas, Tables, Versions
-- =====================================================
-- TODO
