-- Read-only monitoring identity for the dashboard.
-- It sees metadata and a few safe columns. It never gets customer data or SQL text.

CREATE ROLE monitor_ro NOLOGIN;
GRANT monitor_ro TO vault_admin WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
GRANT CONNECT ON DATABASE appdb TO monitor_ro;

CREATE SCHEMA monitor;

-- Temporary Vault users and when they expire (pg_roles is public metadata)
CREATE VIEW monitor.temp_users AS
  SELECT rolname, rolvaliduntil, rolvaliduntil < now() AS expired
  FROM pg_roles
  WHERE rolname LIKE 'v-%';

-- Who is connected. SECURITY DEFINER lets us expose state/backend_start/client_addr of ALL sessions
-- while deliberately leaving out the query text.
CREATE FUNCTION monitor.sessions()
RETURNS TABLE (usename name, application_name text, client_addr inet, state text, backend_start timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT usename, application_name, client_addr, state, backend_start
  FROM pg_catalog.pg_stat_activity
  WHERE backend_type = 'client backend'
$$;
REVOKE ALL ON FUNCTION monitor.sessions() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION monitor.sessions() TO monitor_ro;

-- Group membership (static roles only)
CREATE VIEW monitor.group_members AS
  SELECT g.rolname AS grp, r.rolname AS member, m.admin_option, m.inherit_option, m.set_option
  FROM pg_auth_members m
  JOIN pg_roles g ON g.oid = m.roleid
  JOIN pg_roles r ON r.oid = m.member
  WHERE r.rolname NOT LIKE 'v-%';

-- Table and column privileges in the public schema
CREATE VIEW monitor.privileges AS
  SELECT c.relname::text AS object, NULL::text AS col, r.rolname::text AS grantee, a.privilege_type
  FROM pg_class c
  CROSS JOIN LATERAL aclexplode(c.relacl) a
  JOIN pg_roles r ON r.oid = a.grantee
  WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'r'
  UNION ALL
  SELECT c.relname::text, at.attname::text, r.rolname::text, a.privilege_type
  FROM pg_attribute at
  JOIN pg_class c ON c.oid = at.attrelid
  CROSS JOIN LATERAL aclexplode(at.attacl) a
  JOIN pg_roles r ON r.oid = a.grantee
  WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'r' AND at.attacl IS NOT NULL;

GRANT USAGE ON SCHEMA monitor TO monitor_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA monitor TO monitor_ro;
