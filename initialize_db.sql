-- Extensions

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Initializing tables

-- Object header
CREATE TABLE object (
  object_id UUID PRIMARY KEY UNIQUE NOT NULL DEFAULT uuid_generate_v4(),
  created_at TIMESTAMP NOT NULL DEFAULT now(),
  creating_user_object_id UUID NOT NULL,
);

-- Version Header
CREATE TABLE version (
  version_id UUID PRIMARY KEY UNIQUE NOT NULL DEFAULT uuid_generate_v4(),
  object_id UUID NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT now(),
  creating_user_object_id UUID NOT NULL,
  is_tombstone BOOLEAN DEFAULT FALSE,
);

-- User Version Data
CREATE TABLE user_version (
  version_id UUID NOT NULL,
  username CHARACTER VARYING(256),
  password_hashed CHARACTER VARYING,
  password_salt CHARACTER VARYING,
);

-- Log Version Data
CREATE TABLE log_version (
  version_id UUID NOT NULL,
  creating_user_object_id UUID NOT NULL,
  query CHARACTER VARYING,
);

-- Custom Tables and Versions
