DROP TABLE IF EXISTS users;
CREATE TABLE users (id SERIAL PRIMARY KEY, username VARCHAR(255) NOT NULL UNIQUE, password VARCHAR(255) NOT NULL, secret_note VARCHAR(255));
INSERT INTO users (username, password, secret_note) VALUES ('admin', 'adminSUPER321', 'FLAG{ID0R_D3T3ct3d}');
INSERT INTO users (username, password, secret_note) VALUES ('vasya', 'vasya123', 'My cat has a big...');
INSERT INTO users (username, password, secret_note) VALUES ('petya', 'petya456', 'My dog has a big...');
INSERT INTO users (username, password, secret_note) VALUES ('stepa', 'stepa789', 'My sister has a big...');