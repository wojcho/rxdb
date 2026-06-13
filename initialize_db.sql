-- For testing: sudo docker run --rm --name pg-test -e POSTGRES_PASSWORD=pass -p 5432:5432 -d postgres:18
-- In PostgreSQL VSCodium extension set the following:
-- Server name: localhost
-- Port: 5432
-- User name: postgres
-- Password: pass
-- Database: postgres

-- Extensions

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Security

CREATE USER admin WITH ENCRYPTED PASSWORD "SECRET_HERE";

-- Public schema, any users can read and insert, other operations are forbidden for them
CREATE SCHEMA rxdb_base;
-- TODO

-- Private, only admin can read and insert, other opertations are forbidden for anyone
CREATE SCHEMA rxdb_private;
-- TODO

-- TODO Maybe focus on granting permissions to tables later, after all tables, procedures, functions are created

-- Any user can create their own schemas
-- TODO

-- Initializing tables

-- Object header
CREATE TABLE rxdb_base.object (
  object_id UUID PRIMARY KEY UNIQUE NOT NULL DEFAULT uuid_generate_v4(),
  created_at TIMESTAMP NOT NULL DEFAULT now(),
  creating_user_object_id UUID NOT NULL,
);

-- Version Header
CREATE TABLE rxdb_base.version (
  version_id VARCHAR(1024) PRIMARY KEY UNIQUE NOT NULL,
  object_id UUID NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT now(),
  creating_user_object_id UUID NOT NULL,
  is_property BOOLEAN DEFAULT FALSE, -- Whether that version can be used in graph as an edge
  is_tombstone BOOLEAN DEFAULT FALSE, -- Whether that version is logically removed ()
);

-- User Version Data
CREATE TABLE rxdb_private.user_version (
  version_id VARCHAR(1024) NOT NULL,
  username VARCHAR(256),
  password_hashed VARCHAR,
  password_salt VARCHAR,
);

-- Log Version Data (per schema)
-- CREATE TABLE log_version (
--   version_id UUID NOT NULL,
--   creating_user_object_id UUID NOT NULL,
--   operation VARCHAR,
-- );

-- Procedures and Functions

-- Create User (only admin can run)
-- TODO

-- Update User by Adding New Version (admin and user themselves can run)
-- TODO

-- Create Log (anyone can run)
-- TODO

-- Create Custom Domain (Schema and Log Table) (anoyone can run)
-- TODO

-- Select List of Accessible Schemas (anyone can run, output is different for them)
-- TODO

-- Select Permissions in Schema (anyone can run, output is different for them)
-- TODO

-- Select List of All Tables in Schema (anyone with access to schema can run)
-- TODO

-- Select Table Definition (anyone with access to schema can run)
-- TODO

-- Custom Schemas, Tables, Versions
-- TODO
