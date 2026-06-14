-- For testing:
-- ```
-- sudo docker rm -f pg-test \
-- && sudo docker run --rm --name pg-test \
--   -e POSTGRES_USER=myuser \
--   -e POSTGRES_PASSWORD=pass \
--   -p 5432:5432 -d postgres:18
-- ```
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
    DEFERRABLE INITIALLY DEFERRED
);

-- Version Header
CREATE TABLE IF NOT EXISTS rxdb_base.version (
  version_id VARCHAR(1024) PRIMARY KEY UNIQUE NOT NULL DEFAULT gen_random_uuid()::varchar, -- It is not just UUID, to enable users to set arbitrary version IDs for easier access (weird artifact of that decision is that name clases can be also with old versions, and because of it serving as username, once someone changes their password they also have at once to change their username), that UUID here is a fallback and should be used sparingly
  object_id UUID NOT NULL, -- fk_version_object
  created_at TIMESTAMP NOT NULL DEFAULT now(),
  creating_user_object_id UUID NOT NULL, -- fk_version_creating_user
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
    DEFERRABLE INITIALLY DEFERRED
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

-- {
--   "postgres": ["DELETE","INSERT","MAINTAIN","REFERENCES","SELECT","TRIGGER","TRUNCATE","UPDATE"],
--   "PUBLIC": ["INSERT","SELECT"]
-- }
CREATE OR REPLACE FUNCTION rxdb_base.acl_to_json(
  acl aclitem[]
)
RETURNS jsonb
LANGUAGE sql
STABLE
AS $$
  WITH exploded AS (
    SELECT
      CASE WHEN x.grantee = 0 THEN 'PUBLIC' ELSE grantee_role.rolname END AS grantee,
      x.privilege_type AS privilege
    FROM aclexplode(acl) x
    LEFT JOIN pg_roles grantee_role ON grantee_role.oid = x.grantee
  ),
  grouped AS (
    SELECT grantee, jsonb_agg(privilege ORDER BY privilege) AS privileges
    FROM exploded
    GROUP BY grantee
  )
  SELECT COALESCE(jsonb_object_agg(grantee, privileges), '{}'::jsonb)
  FROM grouped;
$$;

-- {
--   "types": {},
--   "schema": {
--     "acl": {
--       "PUBLIC": [
--         "USAGE"
--       ],
--       "rxdb_admin": [
--         "CREATE",
--         "USAGE"
--       ]
--     },
--     "name": "rxdb_base"
--   },
--   "routines": {
--     "rxdb_base.acl_to_json(aclitem[])": {
--       "acl": {},
--       "owner": "postgres"
--     },
--     "rxdb_base.current_user_object_id()": {
--       "acl": {},
--       "owner": "postgres"
--     },
--     "rxdb_base.select_accessible_schemas()": {
--       "acl": {},
--       "owner": "postgres"
--     },
--     "rxdb_base.insert_log(character varying,jsonb)": {
--       "acl": {},
--       "owner": "postgres"
--     },
--     "rxdb_base.select_schema_permissions(character varying)": {
--       "acl": {},
--       "owner": "postgres"
--     },
--     "rxdb_base.select_table_names_in_schema(character varying)": {
--       "acl": {},
--       "owner": "postgres"
--     },
--     "rxdb_base.select_table_definition(character varying,character varying)": {
--       "acl": {},
--       "owner": "postgres"
--     }
--   },
--   "relations": {
--     "object": {
--       "acl": {
--         "PUBLIC": [
--           "INSERT",
--           "SELECT"
--         ],
--         "postgres": [
--           "DELETE",
--           "INSERT",
--           "MAINTAIN",
--           "REFERENCES",
--           "SELECT",
--           "TRIGGER",
--           "TRUNCATE",
--           "UPDATE"
--         ]
--       },
--       "owner": "postgres"
--     },
--     "version": {
--       "acl": {
--         "PUBLIC": [
--           "INSERT",
--           "SELECT"
--         ],
--         "postgres": [
--           "DELETE",
--           "INSERT",
--           "MAINTAIN",
--           "REFERENCES",
--           "SELECT",
--           "TRIGGER",
--           "TRUNCATE",
--           "UPDATE"
--         ]
--       },
--       "owner": "postgres"
--     },
--     "log_version": {
--       "acl": {
--         "PUBLIC": [
--           "INSERT",
--           "SELECT"
--         ],
--         "postgres": [
--           "DELETE",
--           "INSERT",
--           "MAINTAIN",
--           "REFERENCES",
--           "SELECT",
--           "TRIGGER",
--           "TRUNCATE",
--           "UPDATE"
--         ]
--       },
--       "owner": "postgres"
--     }
--   },
--   "default_privileges": {
--     "tables": {
--       "acl": {
--         "PUBLIC": [
--           "INSERT",
--           "SELECT"
--         ]
--       },
--       "owner": "rxdb_admin",
--       "schema": "rxdb_base"
--     }
--   }
-- }

-- Select Permissions in a Schema, used for reflection purposes (anyone with access to schema can run)
CREATE OR REPLACE FUNCTION rxdb_base.select_schema_permissions(
  schema_name varchar
)
RETURNS jsonb
LANGUAGE plpgsql
AS $$
DECLARE
  schema_oid oid;
  relations_json jsonb;
  routines_json jsonb;
  types_json jsonb;
  default_privileges_json jsonb;
  retval jsonb;
BEGIN
  -- Schema oid
  SELECT oid
  INTO schema_oid
  FROM pg_namespace
  WHERE nspname = schema_name;

  IF schema_oid IS NULL THEN
    RAISE EXCEPTION
      'Schema "%" does not exist',
      schema_name;
  END IF;

  -- Relations
  SELECT COALESCE(
    jsonb_object_agg(
      c.relname,
      jsonb_build_object(
        'owner', owner_role.rolname,
        'acl', rxdb_base.acl_to_json(c.relacl)
      )
      ORDER BY c.relname
    ),
    '{}'::jsonb
  )
  INTO relations_json
  FROM pg_class c
  JOIN pg_roles owner_role
    ON owner_role.oid = c.relowner
  WHERE c.relnamespace = schema_oid
  AND NOT (
    c.relkind = 'i'
    AND EXISTS (
      SELECT 1
      FROM pg_index i
      JOIN pg_constraint con
        ON con.conindid = i.indexrelid
      WHERE i.indexrelid = c.oid
        AND con.contype = 'p'
    )
  );

  -- Routines
  SELECT COALESCE(
    jsonb_object_agg(
      (p.oid::regprocedure::text),
      jsonb_build_object(
        'owner', r.rolname,
        'acl', rxdb_base.acl_to_json(p.proacl)
      )
      ORDER BY (p.oid::regprocedure::text)
    ),
    '{}'::jsonb
  )
  INTO routines_json
  FROM pg_proc p
  JOIN pg_namespace n
    ON n.oid = p.pronamespace
  JOIN pg_roles r
    ON r.oid = p.proowner
  JOIN pg_language l
    ON l.oid = p.prolang
  WHERE p.pronamespace = schema_oid;

  -- Types
  SELECT COALESCE(
    jsonb_object_agg(
      t.typname,
      jsonb_build_object(
        'owner', r.rolname,
        'acl', rxdb_base.acl_to_json(t.typacl)
      )
      ORDER BY t.typname
    ),
    '{}'::jsonb
  )
  INTO types_json
  FROM pg_type t
  JOIN pg_namespace n
    ON n.oid = t.typnamespace
  JOIN pg_roles r
    ON r.oid = t.typowner
  WHERE t.typnamespace = schema_oid
    AND t.typrelid = 0 -- remove automatically generated types of tables
    AND NOT ( -- remove automatically generated array types of tables
      t.typelem != 0
      AND EXISTS (
        SELECT 1
        FROM pg_type base
        WHERE base.oid = t.typelem
          AND base.typnamespace = schema_oid
      )
    );

  -- Default
  SELECT COALESCE(
    jsonb_object_agg(
      CASE d.defaclobjtype
        WHEN 'r' THEN 'tables'
        WHEN 'S' THEN 'sequences'
        WHEN 'f' THEN 'routines'
        WHEN 'T' THEN 'types'
        WHEN 'n' THEN 'schemas'
        WHEN 'd' THEN 'domains'
        WHEN 'c' THEN 'columns'
        ELSE d.defaclobjtype::text
      END,
      jsonb_build_object(
        'owner', owner_role.rolname,
        'schema',
          CASE
            WHEN d.defaclnamespace IS NULL THEN NULL
            ELSE ns.nspname
          END,
        'acl', rxdb_base.acl_to_json(d.defaclacl)
      )
      ORDER BY owner_role.rolname, d.defaclobjtype
    ),
    '[]'::jsonb
  )
  INTO default_privileges_json
  FROM pg_default_acl d
  JOIN pg_roles owner_role
    ON owner_role.oid = d.defaclrole
  LEFT JOIN pg_namespace ns
    ON ns.oid = d.defaclnamespace
  WHERE d.defaclnamespace = schema_oid
    OR d.defaclnamespace IS NULL;

  -- Retval
  SELECT jsonb_build_object(
    'schema',
    jsonb_build_object( -- Schema
      'name', n.nspname,
      'acl', rxdb_base.acl_to_json(n.nspacl)
    ),
    'relations',
    relations_json,
    'routines',
    routines_json,
    'types',
    types_json,
    'default_privileges',
    default_privileges_json
  )
  INTO retval
  FROM pg_namespace n
  WHERE n.oid = schema_oid;

  RETURN retval;
END;
$$;

-- Create Custom Domain/Schema (Schema and Log Table) (anyone can run)
CREATE OR REPLACE PROCEDURE rxdb_base.create_domain (
  domain_name VARCHAR,
  schema_permissions JSONB DEFAULT NULL -- similar to values returned by rxdb_base.select_schema_permissions
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  -- Create schema
  EXECUTE format(
    'CREATE SCHEMA IF NOT EXISTS %I',
    domain_name
  );

  -- Create log table within schema
  EXECUTE format(
    '
    CREATE TABLE IF NOT EXISTS %I.log_version (
      version_id VARCHAR(1024) PRIMARY KEY,
      operation JSONB,
      CONSTRAINT fk_log_version_version_%I
        FOREIGN KEY (version_id)
        REFERENCES rxdb_base.version (version_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
    )',
    domain_name,
    domain_name
  );

  -- Apply permissions if provided
  IF schema_permissions IS NOT NULL THEN
    CALL rxdb_base.update_domain_permissions(domain_name, schema_permissions);
  END IF;

END;
$$;

-- Helper for privilege validity checking (anoyne can run)
CREATE OR REPLACE FUNCTION rxdb_base.assert_valid_privilege(
  privilege_name VARCHAR,
  privilege_target VARCHAR
) RETURNS VARCHAR
LANGUAGE plpgsql
AS $$
BEGIN
  CASE privilege_target -- https://www.postgresql.org/docs/current/ddl-priv.html#PRIVILEGES-SUMMARY-TABLE
    WHEN 'schema' THEN
      IF privilege_name NOT IN ('USAGE', 'CREATE') THEN
        RAISE EXCEPTION 'Wrong schema privilege: %', privilege_name;
      END IF;

    WHEN 'table' THEN
      IF privilege_name NOT IN ('SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER') THEN
        RAISE EXCEPTION 'Wrong table privilege: %', privilege_name;
      END IF;

    WHEN 'function' THEN
      IF privilege_name NOT IN ('EXECUTE') THEN
        RAISE EXCEPTION 'Wrong function privilege: %', privilege_name;
      END IF;

    WHEN 'type' THEN
      IF privilege_name NOT IN ('USAGE') THEN
        RAISE EXCEPTION 'Wrong type privilege: %', privilege_name;
      END IF;

    WHEN 'default' THEN
      IF privilege_name NOT IN ('SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER','EXECUTE') THEN
        RAISE EXCEPTION 'Wrong default privilege: %', privilege_name;
      END IF;
    ELSE
      RAISE EXCEPTION 'Unknown privilege context';
  END CASE;

  RETURN privilege_name;
END;
$$;

-- Helper for privilege revoking on schemas (only schema owner can call)
CREATE OR REPLACE PROCEDURE rxdb_base.revoke_all_schema_grants(
  p_schema_name varchar
)
LANGUAGE plpgsql
AS $$
DECLARE
  role_name text;
BEGIN
  FOR role_name IN
    SELECT DISTINCT
      CASE
        WHEN x.grantee = 0 THEN 'PUBLIC'
        ELSE r.rolname
      END
    FROM pg_namespace n
    CROSS JOIN LATERAL aclexplode(n.nspacl) x
    LEFT JOIN pg_roles r
      ON r.oid = x.grantee
    WHERE n.nspname = p_schema_name
  LOOP
    EXECUTE format(
      'REVOKE ALL ON SCHEMA %I FROM %I',
      p_schema_name,
      role_name
    );
  END LOOP;
END;
$$;

-- Helper for privilege revoking on relations (only schema owner can call)
CREATE OR REPLACE PROCEDURE rxdb_base.revoke_all_relation_grants(
  p_schema_name varchar,
  p_relation_name varchar
)
LANGUAGE plpgsql
AS $$
DECLARE
  role_name text;
BEGIN
  FOR role_name IN
    SELECT DISTINCT
      CASE
        WHEN x.grantee = 0 THEN 'PUBLIC'
        ELSE r.rolname
      END
    FROM pg_class c
    JOIN pg_namespace n
      ON n.oid = c.relnamespace
    CROSS JOIN LATERAL aclexplode(c.relacl) x
    LEFT JOIN pg_roles r
      ON r.oid = x.grantee
    WHERE n.nspname = p_schema_name
      AND c.relname = p_relation_name
  LOOP
    EXECUTE format(
      'REVOKE ALL ON TABLE %I.%I FROM %I',
      p_schema_name,
      p_relation_name,
      role_name
    );
  END LOOP;
END;
$$;
-- Helper for privilege revoking on types (only schema owner can call)
CREATE OR REPLACE PROCEDURE rxdb_base.revoke_all_type_grants(
  p_schema_name varchar,
  p_type_name varchar
)
LANGUAGE plpgsql
AS $$
DECLARE
  role_name text;
BEGIN
  FOR role_name IN
    SELECT DISTINCT
      CASE
        WHEN x.grantee = 0 THEN 'PUBLIC'
        ELSE r.rolname
      END
    FROM pg_type t
    JOIN pg_namespace n
      ON n.oid = t.typnamespace
    CROSS JOIN LATERAL aclexplode(t.typacl) x
    LEFT JOIN pg_roles r
      ON r.oid = x.grantee
    WHERE n.nspname = p_schema_name
      AND t.typname = p_type_name
  LOOP
    EXECUTE format(
      'REVOKE ALL ON TYPE %I.%I FROM %I',
      p_schema_name,
      p_type_name,
      role_name
    );
  END LOOP;
END;
$$;
-- Helper for privilege revoking on routines (only schema owner can call)
CREATE OR REPLACE PROCEDURE rxdb_base.revoke_all_routine_grants(
  p_routine_oid oid
)
LANGUAGE plpgsql
AS $$
DECLARE
  role_name text;
  routine_sig text;
BEGIN
  SELECT p.oid::regprocedure::text
  INTO routine_sig
  FROM pg_proc p
  WHERE p.oid = p_routine_oid;

  FOR role_name IN
    SELECT DISTINCT
      CASE
        WHEN x.grantee = 0 THEN 'PUBLIC'
        ELSE r.rolname
      END
    FROM pg_proc p
    CROSS JOIN LATERAL aclexplode(p.proacl) x
    LEFT JOIN pg_roles r
      ON r.oid = x.grantee
    WHERE p.oid = p_routine_oid
  LOOP
    EXECUTE
      'REVOKE ALL ON ROUTINE '
      || routine_sig
      || ' FROM '
      || quote_ident(role_name);
  END LOOP;
END;
$$;
-- Helper for privilege revoking on default (only schema owner can call)
CREATE OR REPLACE PROCEDURE rxdb_base.revoke_all_default_grants(
  p_owner varchar,
  p_schema varchar,
  p_object_type varchar
)
LANGUAGE plpgsql
AS $$
DECLARE
  role_name text;
  current_acl aclitem[];
BEGIN
  SELECT d.defaclacl
  INTO current_acl
  FROM pg_default_acl d
  JOIN pg_roles r
    ON r.oid = d.defaclrole
  LEFT JOIN pg_namespace n
    ON n.oid = d.defaclnamespace
  WHERE r.rolname = p_owner
    AND n.nspname = p_schema
    AND CASE p_object_type
      WHEN 'TABLES' THEN 'r'
      WHEN 'SEQUENCES' THEN 'S'
      WHEN 'ROUTINES' THEN 'f'
      WHEN 'TYPES' THEN 'T'
    END = d.defaclobjtype;

  IF current_acl IS NULL THEN
    RETURN;
  END IF;

  FOR role_name IN
    SELECT DISTINCT
      CASE
        WHEN x.grantee = 0 THEN 'PUBLIC'
        ELSE r.rolname
      END
    FROM aclexplode(current_acl) x
    LEFT JOIN pg_roles r
      ON r.oid = x.grantee
  LOOP
    EXECUTE format(
      'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I REVOKE ALL ON %s FROM %I',
      p_owner,
      p_schema,
      p_object_type,
      role_name
    );
  END LOOP;
END;
$$;

-- Update Custom Domain/Schema Permissions (only schema owner run)
CREATE OR REPLACE PROCEDURE rxdb_base.update_domain_permissions (
  domain_name VARCHAR,
  schema_permissions JSONB -- similar to values returned by rxdb_base.select_schema_permissions
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  schema_acl JSONB;
  relations_acl JSONB;

  routines_acl JSONB;
  types_acl JSONB;
  defaults_acl JSONB;

  rel_name TEXT;
  rel_acl JSONB;

  routine_sig TEXT;
  routine_acl JSONB;

  type_name TEXT;
  type_acl JSONB;

  role_name TEXT;
  privileges JSONB;
  privilege TEXT;

  object_type TEXT;
  object_acl JSONB;
  object_owner TEXT;
  object_schema TEXT;
  sql_object TEXT;
BEGIN
  -- Check whether schema exists
  IF NOT EXISTS (
    SELECT 1 FROM pg_namespace WHERE nspname = domain_name
  ) THEN
    RAISE EXCEPTION 'Schema "%" does not exist', domain_name;
  END IF;

  -- Set schema-level privileges
  schema_acl := schema_permissions->'schema'->'acl';

  IF schema_acl IS NOT NULL THEN
    -- revoke all from everyone, not just public
    CALL rxdb_base.revoke_all_schema_grants(domain_name);

    FOR role_name, privileges IN
      SELECT * FROM jsonb_each(schema_acl)
    LOOP
      FOR privilege IN
        SELECT jsonb_array_elements_text(privileges)
      LOOP
        privilege := rxdb_base.assert_valid_privilege(privilege, 'schema');
        EXECUTE format(
          'GRANT %I ON SCHEMA %I TO %I',
          privilege,
          domain_name,
          role_name
        );
      END LOOP;
    END LOOP;
  END IF;
  -- Schema owner
  IF schema_permissions->'schema' ? 'owner' THEN
    EXECUTE format(
      'ALTER SCHEMA %I OWNER TO %I',
      domain_name,
      schema_permissions->'schema'->>'owner'
    );
  END IF;

  -- Set table-level privileges
  relations_acl := schema_permissions->'relations';

  IF relations_acl IS NOT NULL THEN
    FOR rel_name, rel_acl IN
      SELECT * FROM jsonb_each(relations_acl)
    LOOP

      -- ensure that table exists
      IF NOT EXISTS (
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = domain_name
          AND table_name = rel_name
      ) THEN
        CONTINUE;
      END IF;

      -- TODO revoke all from everyone, not just public
      CALL rxdb_base.revoke_all_relation_grants(
        domain_name,
        rel_name
      );

      -- grant per-role privileges
      FOR role_name, privileges IN
        SELECT * FROM jsonb_each(rel_acl->'acl')
      LOOP
        FOR privilege IN
          SELECT jsonb_array_elements_text(privileges)
        LOOP
          privilege := rxdb_base.assert_valid_privilege(privilege, 'table');
          EXECUTE format(
            'GRANT %I ON TABLE %I.%I TO %I',
            privilege,
            domain_name,
            rel_name,
            role_name
          );
        END LOOP;
      END LOOP;
      -- Table owner
      IF rel_acl ? 'owner' THEN
        EXECUTE format(
          'ALTER TABLE %I.%I OWNER TO %I',
          domain_name,
          rel_name,
          rel_acl->>'owner'
        );
      END IF;
    END LOOP;
  END IF;

  -- Set routine-level privileges
  routines_acl := schema_permissions->'routines';

  IF routines_acl IS NOT NULL THEN
    FOR routine_sig, routine_acl IN
      SELECT * FROM jsonb_each(routines_acl)
    LOOP

      -- revoke all from everyone, not just public
      CALL rxdb_base.revoke_all_routine_grants(
        routine_oid
      );

      FOR role_name, privileges IN
        SELECT * FROM jsonb_each(routine_acl->'acl')
      LOOP
        FOR privilege IN
          SELECT jsonb_array_elements_text(privileges)
        LOOP
          privilege := rxdb_base.assert_valid_privilege(privilege, 'function');
          EXECUTE format(
            'GRANT %I ON ROUTINE %I TO %I',
            privilege, routine_sig, role_name
          );
        END LOOP;
      END LOOP;
      -- Routine owner
      IF routine_acl ? 'owner' THEN
        EXECUTE format(
          'ALTER ROUTINE %I OWNER TO %I',
          routine_sig,
          routine_acl->>'owner'
        );
      END IF;

    END LOOP;
  END IF;

  -- Set type-level privileges
  types_acl := schema_permissions->'types';

  IF types_acl IS NOT NULL THEN
    FOR type_name, type_acl IN
      SELECT * FROM jsonb_each(types_acl)
    LOOP

      -- revoke all from everyone, not just public
      CALL rxdb_base.revoke_all_type_grants(
        domain_name,
        type_name
      );

      FOR role_name, privileges IN
        SELECT * FROM jsonb_each(type_acl->'acl')
      LOOP
        FOR privilege IN
          SELECT jsonb_array_elements_text(privileges)
        LOOP
          privilege := rxdb_base.assert_valid_privilege(privilege, 'type');
          EXECUTE format(
            'GRANT %I ON TYPE %I.%I TO %I',
            privilege, domain_name, type_name, role_name
          );
        END LOOP;
      END LOOP;
      -- Type owner
      IF type_acl ? 'owner' THEN
        EXECUTE format(
          'ALTER TYPE %I.%I OWNER TO %I',
          domain_name,
          type_name,
          type_acl->>'owner'
        );
      END IF;

    END LOOP;
  END IF;

  -- Set default schema-level privileges
  defaults_acl := schema_permissions->'default_privileges';

  IF defaults_acl IS NOT NULL THEN
    FOR object_type, object_acl IN
      SELECT * FROM jsonb_each(defaults_acl)
    LOOP

      object_owner  := object_acl->>'owner';
      object_schema := object_acl->>'schema';

      CASE object_type
        WHEN 'tables' THEN
          sql_object := 'TABLES';

        WHEN 'sequences' THEN
          sql_object := 'SEQUENCES';

        WHEN 'routines' THEN
          sql_object := 'ROUTINES';

        WHEN 'types' THEN
          sql_object := 'TYPES';

        ELSE
          CONTINUE;
      END CASE;

      -- revoke all from everyone, not just public
      CALL rxdb_base.revoke_all_default_grants(
        object_owner,
        object_schema,
        sql_object
      );

      -- Grant configured privileges
      FOR role_name, privileges IN
        SELECT * FROM jsonb_each(object_acl->'acl')
      LOOP

        FOR privilege IN
          SELECT jsonb_array_elements_text(privileges)
        LOOP

          privilege := rxdb_base.assert_valid_privilege(
            privilege,
            'default'
          );

          EXECUTE format(
            'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I GRANT %I ON %I TO %I',
            object_owner,
            object_schema,
            privilege,
            sql_object,
            role_name
          );

        END LOOP;
      END LOOP;
    END LOOP;
  END IF;

END;
$$;

-- Tables/Types

-- Select List of All Tables in Schema (anyone with access to schema can run)
CREATE OR REPLACE FUNCTION rxdb_base.select_table_names_in_schema(
  domain_name VARCHAR
)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
  retval JSONB;
BEGIN
  SELECT jsonb_agg(table_name)
  INTO retval
  FROM information_schema.tables
  WHERE table_schema = domain_name
    AND table_type = 'BASE TABLE';
  RETURN COALESCE(retval, '[]'::jsonb);
END;
$$;

-- {
--   "columns": [
--     {
--       "name": "version_id",
--       "type": "character varying",
--       "default": null,
--       "nullable": false
--     },
--     {
--       "name": "operation",
--       "type": "jsonb",
--       "default": null,
--       "nullable": true
--     }
--   ],
--   "indexes": {
--     "rxdb_base.log_version_pkey": {
--       "unique": true,
--       "columns": [
--         "version_id"
--       ]
--     }
--   },
--   "primary_key": [
--     "version_id"
--   ],
--   "foreign_keys": {
--     "fk_log_version_version_rxdb_base": {
--       "columns": [
--         "version_id"
--       ],
--       "on_delete": "RESTRICT",
--       "on_update": "RESTRICT",
--       "references": {
--         "table": "version",
--         "schema": "rxdb_base",
--         "columns": [
--           "version_id"
--         ]
--       }
--     }
--   }
-- }

-- Select Type/Table Definition (anyone with access to schema can run)
CREATE OR REPLACE FUNCTION rxdb_base.select_table_definition(
  domain_and_schema_name VARCHAR, -- name conflict, otherwise it would be called as elsewhere domain_name
  type_name VARCHAR
)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
  retval JSONB;
BEGIN
  WITH cols AS (
    SELECT
      c.column_name,
      c.data_type,
      c.is_nullable,
      c.column_default
    FROM information_schema.columns c
    WHERE c.table_schema = domain_and_schema_name
      AND c.table_name = type_name
  ),

  col_json AS (
    SELECT jsonb_agg(
      jsonb_build_object(
        'name', column_name,
        'type', data_type,
        'nullable', (is_nullable = 'YES'),
        'default',
        column_default
      )
    ) AS columns
    FROM cols
  ),

  pk AS (
    SELECT
      jsonb_agg(a.attname ORDER BY k.n) AS columns
    FROM pg_constraint c
    JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, n) ON true
    JOIN pg_attribute a
      ON a.attrelid = c.conrelid AND a.attnum = k.attnum
    WHERE c.contype = 'p'
      AND c.conrelid = format('%I.%I', domain_and_schema_name, type_name)::regclass
  ),

  fks AS (
    SELECT jsonb_object_agg(
      c.conname,
      jsonb_build_object(
        'columns',
          (SELECT jsonb_agg(a1.attname ORDER BY k1.n)
           FROM unnest(c.conkey) WITH ORDINALITY AS k1(attnum, n)
           JOIN pg_attribute a1
             ON a1.attrelid = c.conrelid AND a1.attnum = k1.attnum),

        'references',
          jsonb_build_object(
            'schema', nsp.nspname,
            'table', cls.relname,

            'columns',
              (SELECT jsonb_agg(a2.attname ORDER BY k2.n)
               FROM unnest(c.confkey) WITH ORDINALITY AS k2(attnum, n)
               JOIN pg_attribute a2
                 ON a2.attrelid = c.confrelid AND a2.attnum = k2.attnum)
          ),

        'on_update',
          CASE c.confupdtype
            WHEN 'c' THEN 'CASCADE'
            WHEN 'r' THEN 'RESTRICT'
            WHEN 'n' THEN 'SET_NULL'
            WHEN 'd' THEN 'SET_DEFAULT'
            ELSE 'NO_ACTION'
          END,

        'on_delete',
          CASE c.confdeltype
            WHEN 'c' THEN 'CASCADE'
            WHEN 'r' THEN 'RESTRICT'
            WHEN 'n' THEN 'SET_NULL'
            WHEN 'd' THEN 'SET_DEFAULT'
            ELSE 'NO_ACTION'
          END
      )
    ) AS fks
    FROM pg_constraint c
    JOIN pg_class cls ON cls.oid = c.confrelid
    JOIN pg_namespace nsp ON nsp.oid = cls.relnamespace
    WHERE c.contype = 'f'
      AND c.conrelid = format('%I.%I', domain_and_schema_name, type_name)::regclass
  ),

  indexes AS (
    SELECT jsonb_object_agg(
      i.indexrelid::regclass::text,
      jsonb_build_object(
        'unique', i.indisunique,

        'columns',
          (SELECT jsonb_agg(a.attname ORDER BY k.n)
           FROM unnest(i.indkey) WITH ORDINALITY AS k(attnum, n)
           JOIN pg_attribute a
             ON a.attrelid = i.indrelid AND a.attnum = k.attnum)
      )
    ) AS indexes
    FROM pg_index i
    JOIN pg_class c ON c.oid = i.indrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = domain_and_schema_name
      AND c.relname = type_name
  )

  SELECT jsonb_build_object(
    'columns', (SELECT columns FROM col_json),
    'primary_key', (SELECT columns FROM pk),
    'foreign_keys', (SELECT fks FROM fks),
    'indexes', (SELECT indexes FROM indexes)
  )
  INTO retval;

  RETURN COALESCE(retval, '{}'::jsonb);
END;
$$;

-- Create Custom Type/Table (anyone with access to schema can run)
CREATE OR REPLACE PROCEDURE rxdb_base.create_type(
  domain_name VARCHAR,
  type_name VARCHAR,
  table_definition JSONB -- as returned by rxdb_base.select_table_definition
)
LANGUAGE plpgsql
AS $$
DECLARE
  col JSONB;
  cols_sql VARCHAR := '';
  pk_cols VARCHAR := '';
  pk_sql VARCHAR;
  fk RECORD; -- (key TEXT, value JSONB);
  idx RECORD; -- (key TEXT, value JSONB);

  full_table_ident VARCHAR := format('%I.%I', domain_name, type_name);
BEGIN
  -- Validate definition
  IF NOT rxdb_base.is_valid_table_definition(domain_name, type_name, table_definition) THEN
    RAISE EXCEPTION 'Invalid table definition for %.%', domain_name, type_name;
  END IF;

  -- Build column definitions
  FOR col IN
    SELECT * FROM jsonb_array_elements(COALESCE(table_definition->'columns', '[]'::jsonb))
  LOOP
    cols_sql := cols_sql || format(
      '%I %s %s %s, ',
      col->>'name',
      col->>'type',
      CASE
        WHEN (col ? 'nullable') AND (col->>'nullable')::boolean = false THEN 'NOT NULL'
        ELSE ''
      END,
      CASE
        WHEN col ? 'default' THEN
          CASE
            WHEN col->'default' = 'null'::jsonb THEN
              'DEFAULT NULL'
            ELSE
              'DEFAULT ' || quote_literal(col->>'default')
          END
        ELSE
          ''
      END
    );
  END LOOP;

  cols_sql := regexp_replace(cols_sql, ',\s*$', '');

  -- Primary key
  SELECT string_agg(quote_ident(value), ', ')
  INTO pk_cols
  FROM jsonb_array_elements_text(table_definition->'primary_key');

  pk_sql := format(', PRIMARY KEY (%s)', pk_cols);

  -- Create table
  EXECUTE format(
    'CREATE TABLE IF NOT EXISTS %s (%s %s)',
    full_table_ident,
    cols_sql,
    pk_sql
  );

  -- Foreign keys
  IF table_definition ? 'foreign_keys' THEN
    FOR fk IN
      SELECT * FROM jsonb_each(table_definition->'foreign_keys')
    LOOP
      EXECUTE format(
        'ALTER TABLE %s ADD CONSTRAINT %I FOREIGN KEY (%s) REFERENCES %I.%I (%s)
         ON UPDATE %s ON DELETE %s',
        full_table_ident,
        fk.key,
        (SELECT string_agg(quote_ident(v), ', ')
         FROM jsonb_array_elements_text(fk.value->'columns') v),
        fk.value->'references'->>'schema',
        fk.value->'references'->>'table',
        (SELECT string_agg(quote_ident(v), ', ')
         FROM jsonb_array_elements_text(fk.value->'references'->'columns') v),
        fk.value->>'on_update',
        fk.value->>'on_delete'
      );
    END LOOP;
  END IF;

  -- Indexes
  IF table_definition ? 'indexes' THEN
    FOR idx IN
      SELECT * FROM jsonb_each(table_definition->'indexes')
    LOOP
      EXECUTE format(
        'CREATE INDEX IF NOT EXISTS %I ON %s (%s)',
        idx.key,
        full_table_ident,
        (SELECT string_agg(quote_ident(v), ', ')
         FROM jsonb_array_elements_text(idx.value->'columns') v)
      );
    END LOOP;
  END IF;
END;
$$;

-- Return true if table_definition has the required columns, indexes, primary keys, foreign keys with appropriate properties (anyone can call)
CREATE OR REPLACE FUNCTION rxdb_base.is_valid_table_definition(
  domain_name VARCHAR,
  type_name VARCHAR,
  table_definition JSONB -- as returned by rxdb_base.select_table_definition, {"columns": ..., "indexes", "primary_key": ..., "foreign_keys": ...}
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
  required_column_found BOOLEAN;
  required_pk_found BOOLEAN;
  required_index_found BOOLEAN;
  required_fk_found BOOLEAN;
BEGIN
  -- check that table_definition has required column
  -- "columns": [
  --   {
  --     "name": "version_id",
  --     "type": "character varying",
  --     "default": null, (must be present, has to be null)
  --     "nullable": false
  --   },
  --   <... any other columns can appear or can also not appear>
  -- ]
  SELECT EXISTS (
    SELECT 1
    FROM jsonb_array_elements(
      COALESCE(table_definition->'columns', '[]'::jsonb)
    ) AS c
    WHERE c @> jsonb_build_object(
      'name', 'version_id',
      'type', 'character varying',
      'nullable', false
    )
    AND (
      (c ? 'default') -- key must be present
      AND (c->'default' = 'null'::jsonb) -- value must be JSON null
    )
  )
  INTO required_column_found;

  IF NOT required_column_found THEN
    RETURN FALSE;
  END IF;

  -- check that table_definition has appropriate indexes
  -- "indexes": {
  --   "<domain_name>.<type_name>_pkey": { (name not checked)
  --     "unique": true,
  --     "columns": [
  --       "version_id" (only this, not subset)
  --     ]
  --   },
  --   <... any other indexes can appear or can also not appear>
  -- },
  SELECT EXISTS (
    SELECT 1
    FROM jsonb_each(
      COALESCE(table_definition->'indexes', '{}'::jsonb)
    ) AS idx(name, def)
    WHERE def @> jsonb_build_object(
      'unique', true,
      'columns', jsonb_build_array('version_id')
    )
  )
  INTO required_index_found;

  IF NOT required_index_found THEN
    RETURN FALSE;
  END IF;

  -- check that table_definition has
  -- "primary_key": [
  --   "version_id"
  -- ], (no other pk columns)
  SELECT
    COALESCE(table_definition->'primary_key', '[]'::jsonb)
      = jsonb_build_array('version_id')
  INTO required_pk_found;

  IF NOT required_pk_found THEN
    RETURN FALSE;
  END IF;

  -- check that table_definition has
  -- "foreign_keys": {
  --   "fk_<table_name>_version_<schema_name>": { (name not checked)
  --     "columns": [
  --       "version_id"
  --     ],
  --     "on_delete": "RESTRICT",
  --     "on_update": "RESTRICT",
  --     "references": {
  --       "table": "version",
  --       "schema": "rxdb_base",
  --       "columns": [
  --         "version_id"
  --       ]
  --     }
  --   },
  --   <... any other foreign keys can appear or can also not appear>
  -- }
  SELECT EXISTS (
    SELECT 1
    FROM jsonb_each(
      COALESCE(table_definition->'foreign_keys', '{}'::jsonb)
    ) AS fk(name, def)
    WHERE def @> jsonb_build_object(
      'columns', jsonb_build_array('version_id'),
      'on_update', 'RESTRICT',
      'on_delete', 'RESTRICT',
      'references', jsonb_build_object(
        'schema', 'rxdb_base',
        'table', 'version',
        'columns', jsonb_build_array('version_id')
      )
    )
  )
  INTO required_fk_found;

  IF NOT required_fk_found THEN
    RETURN FALSE;
  END IF;

  -- If not returned earlier then it is correct
  RETURN TRUE;
END;
$$;

-- Pre-fill (anyone can call)
CREATE OR REPLACE FUNCTION rxdb_base.prefill_table_definition(
  domain_name VARCHAR,
  type_name VARCHAR,
  table_definition JSONB -- as returned by rxdb_base.select_table_definition
)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
  retval JSONB := COALESCE(table_definition, '{}'::jsonb);
  cols JSONB;
  idxs JSONB;
  fks JSONB;
  pk JSONB;
  required_col JSONB := jsonb_build_object(
    'name', 'version_id',
    'type', 'character varying',
    'default', 'null'::jsonb,
    'nullable', false
  );
  required_index_def JSONB := jsonb_build_object(
    'unique', true,
    'columns', jsonb_build_array('version_id')
  );
  required_fk_def JSONB := jsonb_build_object(
    'columns', jsonb_build_array('version_id'),
    'on_delete', 'RESTRICT',
    'on_update', 'RESTRICT',
    'references', jsonb_build_object(
      'table', 'version',
      'schema', 'rxdb_base',
      'columns', jsonb_build_array('version_id')
    )
  );
  required_index_name TEXT := format('%I.%I_pkey', domain_name, type_name);
  required_fk_name TEXT := format('fk_%I_version_rxdb_base', type_name);
BEGIN
  -- add the required column representations under column keys
  -- "columns": [
  --   {
  --     "name": "version_id",
  --     "type": "character varying",
  --     "default": null,
  --     "nullable": false
  --   },
  --   <... any other columns can appear or can also not appear>
  -- ]
  -- Ensure "columns" array exists
  cols := COALESCE(retval->'columns', '[]'::jsonb);
  -- If a column with same name exists, try to merge/override its properties to ensure required properties are present
  IF NOT EXISTS (
    SELECT 1 FROM jsonb_array_elements(cols) AS c
    WHERE c->>'name' = 'version_id'
  ) THEN
    -- required column has to be first
    cols := jsonb_build_array(required_col) || cols;
  ELSE
    -- replace existing element with merged version that ensures required properties
    cols := (
      SELECT jsonb_agg(
        CASE
          WHEN elem->>'name' = 'version_id' THEN
            -- keep other keys from existing element but force type, nullable and ensure default key exists with null value
            (elem - 'type' - 'nullable' - 'default') || required_col
          ELSE
            elem
        END
      )
      FROM jsonb_array_elements(cols) AS t(elem)
    );
  END IF;
  retval := retval || jsonb_build_object('columns', cols);

  -- add the required index, retain other indexes
  -- "indexes": {
  --   "<domain_name>.<type_name>_pkey": {
  --     "unique": true,
  --     "columns": [
  --       "version_id"
  --     ]
  --   },
  --   <... any other indexes can appear or can also not appear>
  -- },
  -- Ensure "indexes" object exists
  idxs := COALESCE(retval->'indexes', '{}'::jsonb);
  IF NOT (EXISTS (
    SELECT 1 FROM jsonb_each(idxs) AS i(name, def)
    WHERE def @> jsonb_build_object(
      'unique', true,
      'columns', jsonb_build_array('version_id')
    )
  )) THEN
    -- add or overwrite the required index name with required_index_def
    idxs := idxs || jsonb_build_object(required_index_name, required_index_def);
  END IF;
  retval := retval || jsonb_build_object('indexes', idxs);

  -- add the required primary key
  -- "primary_key": [
  --   "version_id"
  -- ]
  pk := jsonb_build_array('version_id');
  retval := retval || jsonb_build_object('primary_key', pk);

  -- add the required foreign keys, retain other foreign keys
  -- "foreign_keys": {
  --   "fk_<table_name>_version_<schema_name>": {
  --     "columns": [
  --       "version_id"
  --     ],
  --     "on_delete": "RESTRICT",
  --     "on_update": "RESTRICT",
  --     "references": {
  --       "table": "version",
  --       "schema": "rxdb_base",
  --       "columns": [
  --         "version_id"
  --       ]
  --     }
  --   },
  --   <... any other foreign keys can appear or can also not appear>
  -- }
  -- Ensure "foreign_keys" object exists
  fks := COALESCE(retval->'foreign_keys', '{}'::jsonb);
  IF NOT (EXISTS (
    SELECT 1 FROM jsonb_each(fks) AS fk(name, def)
    WHERE def @> required_fk_def
  )) THEN
    fks := fks || jsonb_build_object(required_fk_name, required_fk_def);
  END IF;
  retval := retval || jsonb_build_object('foreign_keys', fks);

  -- It should be ready by now so return
  RETURN retval;
END;
$$;

-- Helper function for rxdb_base.insert_custom, rxdb_base.update_custom
CREATE OR REPLACE FUNCTION rxdb_base.is_valid_custom_mutate_payload(
  domain_name VARCHAR,
  type_name VARCHAR,
  new_data JSONB
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
  wrong_columns VARCHAR[];
  column_count INT;
  row_index INT;
  row_length INT;
  row JSONB;
BEGIN
  -- Validate new_data
  IF new_data IS NULL THEN
    RAISE EXCEPTION 'new_data cannot be null';
  END IF;
  IF NOT (new_data ? 'columns') THEN
    RAISE EXCEPTION 'new_data must contain key "columns"';
  END IF;
  IF NOT (new_data ? 'data') THEN
    RAISE EXCEPTION 'new_data must contain key "data"';
  END IF;
  IF jsonb_typeof(new_data->'columns') <> 'array' THEN
    RAISE EXCEPTION '"columns" must be an array';
  END IF;
  IF jsonb_typeof(new_data->'data') <> 'array' THEN
    RAISE EXCEPTION '"data" must be an array';
  END IF;
  IF jsonb_array_length(new_data->'data') = 0 THEN
    RAISE EXCEPTION '"data" cannot be empty';
  END IF;
  column_count := jsonb_array_length(new_data->'columns');
  IF column_count = 0 THEN
    RAISE EXCEPTION '"columns" cannot be empty';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM (
      SELECT c, count(*) AS cnt
      FROM jsonb_array_elements_text(new_data->'columns') t(c)
      GROUP BY c
      HAVING count(*) > 1
    ) dup
  ) THEN
    RAISE EXCEPTION 'Duplicate column names are not allowed';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM jsonb_array_elements(new_data->'columns') c
    WHERE jsonb_typeof(c) <> 'string'
  ) THEN
    RAISE EXCEPTION 'All column names must be strings';
  END IF;

  -- check whether all arrays in "data" have same length, consistent with amount of columns
  row_index := 0;
  FOR row IN
    SELECT value
    FROM jsonb_array_elements(new_data->'data')
  LOOP
    IF jsonb_typeof(row) <> 'array' THEN
      RAISE EXCEPTION
        'data[%] must be an array',
        row_index;
    END IF;
    row_length := jsonb_array_length(row);
    IF row_length <> column_count THEN
      RAISE EXCEPTION
        'data[%] has % values but % columns were specified',
        row_index,
        row_length,
        column_count;
    END IF;
    row_index := row_index + 1;
  END LOOP;

  -- check whether table exists
  IF NOT EXISTS (
    SELECT 1
    FROM information_schema.tables t
    WHERE t.table_schema = domain_name
      AND t.table_name   = type_name
  ) THEN
    RAISE EXCEPTION
      'Table %.% does not exist',
      domain_name,
      type_name;
  END IF;

  -- check whether all mentioned columns exist in target table, whether there are no unknown columns (not all columns have to be provided, some can take defaults)
  SELECT array_agg(supplied.col)
  INTO wrong_columns
  FROM jsonb_array_elements_text(new_data->'columns') AS supplied(col)
  WHERE NOT EXISTS (
    SELECT 1
    FROM information_schema.columns c
    WHERE c.table_schema = domain_name
      AND c.table_name   = type_name
      AND c.column_name  = supplied.col
  );
  IF wrong_columns IS NOT NULL THEN
    RAISE EXCEPTION
      'Unknown columns for %.%: %',
      domain_name,
      type_name,
      array_to_string(wrong_columns, ', ');
  END IF;

  -- If not raised before then it is correct
  RETURN TRUE;
END;
$$;

-- Insert into Custom Type/Table (anyone with insert access to table domain_name.type_name can run)
CREATE OR REPLACE PROCEDURE rxdb_base.insert_custom(
  domain_name VARCHAR, -- schema name
  type_name VARCHAR, -- table name
  new_data JSONB -- {"columns": ["col0", "col1", ...], "data": [["val00", "val01", ...], ["val10", "val11", ...]]}
)
LANGUAGE plpgsql
AS $$
DECLARE
  current_creating_user_object_id UUID;
  target_object_ids UUID[];
BEGIN
  -- Validate new_data
  PERFORM rxdb_base.is_valid_custom_mutate_payload(
    domain_name,
    type_name,
    new_data
  );

  -- Find object ID of current user
  current_creating_user_object_id := rxdb_base.current_user_object_id();

  -- Create one object for each incoming row (objects here are just vessels for versions, their identity becomes meaningful only afterwards)
  WITH inserted_objects AS (
    INSERT INTO rxdb_base.object (
      creating_user_object_id
    )
    SELECT current_creating_user_object_id
    FROM generate_series(1, row_count)
    RETURNING object_id
  )
  SELECT array_agg(object_id ORDER BY object_id)
  INTO target_object_ids
  FROM inserted_objects;
  
  -- Delegate version creation and custom-table insert to rxdb_base.update_custom
  CALL rxdb_base.update_custom(
    domain_name,
    type_name,
    target_object_ids,
    new_data
  );
END;
$$;

-- Update existing objects by adding new versions to them (anyone with insert access to table domain_name.type_name can run)
CREATE OR REPLACE PROCEDURE rxdb_base.update_custom(
  domain_name VARCHAR, -- schema name
  type_name VARCHAR, -- table name
  target_object_ids UUID[], -- ids of target objects from table rxdb_base.object
  new_data JSONB -- {"columns": ["col0", "col1", ...], "data": [["val00", "val01", ...], ["val10", "val11", ...]]}
)
LANGUAGE plpgsql
AS $$
DECLARE
  current_creating_user_object_id UUID;

  version_id_col_idx INT;

  supplied_columns VARCHAR[];
  effective_columns VARCHAR[];

  target_version_ids VARCHAR[] := ARRAY[]::VARCHAR[];

  col_defs VARCHAR;
  insert_sql VARCHAR;

  transformed_data JSONB := '[]'::jsonb;

  i INT;
  row JSONB;
BEGIN
  -- Validate new_data
  PERFORM rxdb_base.is_valid_custom_mutate_payload(
    domain_name,
    type_name,
    new_data
  );
  -- validate that length(new_data.data) = length(target_object_ids)
  IF jsonb_array_length(new_data->'data')
   <> array_length(target_object_ids, 1)
  THEN
    RAISE EXCEPTION
      'Expected % rows but received %',
      array_length(target_object_ids, 1),
      jsonb_array_length(new_data->'data');
  END IF;

  current_creating_user_object_id := rxdb_base.current_user_object_id();

  -- It answers the question, at which index version_id is in columns, if it is there at all
  version_id_col_idx := NULL;
  SELECT ordinality - 1 -- Ordinality starts from 1, convert to starting from 0
  INTO version_id_col_idx
  FROM jsonb_array_elements_text(new_data->'columns')
    WITH ORDINALITY t(col, ordinality)
  WHERE col = 'version_id'
  LIMIT 1;

  -- Insert Version
  -- if there is provided column "version_id", then for each of values in arrays from data array, using values at that column index, create new version ids
  -- else gather obtained default values, later use them in INSERTs
  FOR i IN 0 .. jsonb_array_length(new_data->'data') - 1
  LOOP
    row := (new_data->'data')->i;

    IF version_id_col_idx IS NOT NULL THEN
      target_version_ids := array_append(
        target_version_ids,
        row->>version_id_col_idx
      );

      INSERT INTO rxdb_base.version (
        version_id,
        object_id,
        creating_user_object_id
      ) VALUES (
        row->>version_id_col_idx,
        target_object_ids[i + 1],
        current_creating_user_object_id
      );
    ELSE
      INSERT INTO rxdb_base.version (
        object_id,
        creating_user_object_id
      ) VALUES (
        target_object_ids[i + 1],
        current_creating_user_object_id
      )
      RETURNING version_id
      INTO target_version_ids[i + 1];
    END IF;

    target_version_ids := array_append(
        target_version_ids,
        used_version_id
      );
  END LOOP;
  -- Now target_version_ids[1] corresponds to target_object_ids[1] which corresponds to new_data.data[0]

  -- Build effective columns

  -- Provided version_ids
  SELECT array_agg(col ORDER BY ordinality)
  INTO supplied_columns
  FROM jsonb_array_elements_text(new_data->'columns')
    WITH ORDINALITY t(col, ordinality);

  -- Get table column types (for proper casts)
  SELECT string_agg(
    format('%I %s', column_name, data_type),
    ', '
    ORDER BY ordinal_position
  )
  INTO col_defs
  FROM information_schema.columns
  WHERE table_schema = domain_name
    AND table_name   = type_name;

  -- Inject version_id column if it was not provided
  IF version_id_col_idx IS NULL THEN
    FOR i IN 0 .. jsonb_array_length(new_data->'data') - 1 LOOP
      transformed_data := transformed_data || jsonb_build_array(
        jsonb_build_array(
          target_version_ids[i + 1]
        ) || (new_data->'data'->i)
      );
    END LOOP;

    new_data := jsonb_build_object(
      'columns', to_jsonb(effective_columns),
      'data', transformed_data
    );
  END IF;

  -- Build column list and execute inserts into target table dynamically
  -- Expect new_data = {"columns": ["col0","col1",...], "data": [...]}

  -- In all tables representing custom types, version_id column with type VARCHAR(1024) is mandatory
  -- All custom tables should have one column defined the following way:
  -- version_id VARCHAR(1024) PRIMARY KEY REFERENCES rxdb_base.version(version_id)

  insert_sql := format(
    $sql$
      INSERT INTO %I.%I (%s)
      SELECT %s
      FROM jsonb_to_recordset($1) AS x(%s)
    $sql$,
    domain_name,
    type_name,
    array_to_string(ARRAY(
      SELECT format('%I', c)
      FROM unnest(effective_columns) c
    ), ', '),
    array_to_string(ARRAY(
      SELECT format('%I', c)
      FROM unnest(effective_columns) c
    ), ', '),
    col_defs
  );

  EXECUTE insert_sql USING new_data->'data';
END;
$$;

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

-- Create first user, rxdb_admin (which is the user logged in present session, but has no associated object yet)

BEGIN;
-- To avert constraint fk_object_creating_user on rxdb_base.object, fk_version_creating_user on rxdb_base.version
SET CONSTRAINTS ALL DEFERRED;
-- do what is usually done in rxdb_private.create_user(), but set user object uuid as '00000000-0000-0000-0000-000000000000', and do not create database user, but only create user object
DO
$$
DECLARE
  new_object_id UUID;
  new_password_hashed VARCHAR;
  current_creating_user_object_id UUID := '11111111-1111-1111-1111-111111111111'::uuid;
  new_username VARCHAR := 'rxdb_admin';
BEGIN
  new_password_hashed := crypt('SECRET_HERE', gen_salt('bf'));
  EXECUTE format(
    'GRANT rxdb_user TO %I',
    new_username
  );
  INSERT INTO rxdb_base.object(
    object_id,
    creating_user_object_id
  ) VALUES (
    current_creating_user_object_id, -- Initial user is self-created
    current_creating_user_object_id
  ) RETURNING object_id
    INTO new_object_id;
  INSERT INTO rxdb_base.version(
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
END
$$ LANGUAGE plpgsql;
COMMIT;

-- =====================================================
-- Custom types
-- =====================================================

-- DO $$
-- DECLARE
--   obj jsonb;
-- BEGIN
--   WITH def AS (
--     SELECT rxdb_base.prefill_table_definition('rxdb_base','testing', $json$
--     {
--       "columns": [
--         {
--           "name": "abc",
--           "type": "integer",
--           "default": null,
--           "nullable": false
--         }
--       ]
--     }
--     $json$::jsonb) AS obj
--   )
--   SELECT def.obj INTO obj FROM def;
--   CALL rxdb_base.create_type('rxdb_base','testing', obj);
-- END $$;

-- Image
-- version_id VARCHAR(1024)
-- image BLOB
-- embedding VECTOR(512) (with vector index)

-- Article
-- version_id VARCHAR(1024)
-- background_image UUID (FK rxdb_base.object.object_id)
-- main_image object (FK rxdb_base.object.object_id)
-- main_text TEXT (with fulltext search index)

-- Forum Thread
-- version_id VARCHAR(1024)
-- parent_forum_thread_object_id VARCHAR(1024) (FK rxdb_base.object.object_id)
-- is_leaf BOOLEAN
-- description TEXT (with fulltext search index)

-- Forum Post
-- version_id VARCHAR(1024)
-- forum_thread_object_id VARCHAR(1024) (FK rxdb_base.object.object_id)
-- Main text TEXT (with fulltext search index)

-- Chat Message
-- version_id VARCHAR(1024)
-- domain_name VARCHAR

-- Notebook
-- version_id VARCHAR(1024)
-- description TEXT (with fulltext search index)

-- Notebook Cell
-- version_id VARCHAR(1024)
-- forum_thread_object_id VARCHAR(1024) (FK rxdb_base.object.object_id)
-- main_code TEXT (with fulltext search index)
-- is_hideable BOOLEAN
