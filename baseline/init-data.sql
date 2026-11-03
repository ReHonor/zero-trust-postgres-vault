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
