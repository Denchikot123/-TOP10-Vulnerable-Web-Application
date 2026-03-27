CREATE TABLE users (id UUID DEFAULT RANDOM_UUID() PRIMARY KEY, username VARCHAR(255), secret_note VARCHAR(255));
INSERT INTO users VALUES ('admin', 'FLAG{ID0R_D3T3ct3d}')
INSERT INTO users VALUES ('vasya', 'My cat has a big...')
INSERT INTO users VALUES ('petya', 'My dog has a big...')
INSERT INTO users VALUES ('stepa', 'My sister has a big...')