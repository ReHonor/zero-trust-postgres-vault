-- Executed once at first start, as postgres, connected to appdb.
-- :'vault_admin_password' is a psql variable passed by 01-init.sh (no hardcoded secrets).

CREATE EXTENSION IF NOT EXISTS pgaudit;

-- Nothing is open by default
REVOKE ALL ON DATABASE appdb FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- Group roles hold the privileges (cannot log in)
CREATE ROLE app_rw     NOLOGIN;
CREATE ROLE analyst_ro NOLOGIN;
CREATE ROLE dba_admin  NOLOGIN;

-- The account Vault uses to create and drop temporary users
SET pgaudit.log = 'none';  -- keep the password out of the audit log
CREATE ROLE vault_admin WITH LOGIN CREATEROLE PASSWORD :'vault_admin_password';
RESET pgaudit.log;
GRANT app_rw, analyst_ro, dba_admin TO vault_admin WITH ADMIN TRUE, INHERIT FALSE;
GRANT pg_signal_backend TO vault_admin;

GRANT CONNECT ON DATABASE appdb TO vault_admin, app_rw, analyst_ro, dba_admin;
GRANT USAGE ON SCHEMA public TO app_rw, analyst_ro, dba_admin;

-- Sample schema with fake data (national_id is the sensitive column)
CREATE TABLE customers (
  id          serial PRIMARY KEY,
  full_name   text NOT NULL,
  email       text NOT NULL,
  city        text NOT NULL,
  national_id text NOT NULL
);

CREATE TABLE orders (
  id          serial PRIMARY KEY,
  customer_id integer NOT NULL REFERENCES customers(id),
  product     text NOT NULL,
  amount_mad  numeric(10,2) NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

INSERT INTO customers (full_name, email, city, national_id) VALUES
  ('Amina El Idrissi',  'amina@example.test',  'Fes',        'AB123456'),
  ('Youssef Benali',    'youssef@example.test','Casablanca', 'CD234567'),
  ('Salma Ouazzani',    'salma@example.test',  'Rabat',      'EF345678'),
  ('Karim Haddad',      'karim@example.test',  'Tangier',    'GH456789'),
  ('Nadia Chraibi',     'nadia@example.test',  'Marrakech',  'IJ567890');

INSERT INTO orders (customer_id, product, amount_mad) VALUES
  (1, 'Laptop',     8500.00),
  (2, 'Phone',      4200.50),
  (3, 'Headphones',  650.00),
  (4, 'Monitor',    2300.00),
  (5, 'Keyboard',    480.75),
  (1, 'Mouse',       150.00);

-- Least-privilege grants
GRANT SELECT, INSERT, UPDATE ON customers, orders TO app_rw;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_rw;

GRANT SELECT ON orders TO analyst_ro;
GRANT SELECT (id, full_name, city) ON customers TO analyst_ro;

GRANT CREATE ON SCHEMA public TO dba_admin;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO dba_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO dba_admin;
