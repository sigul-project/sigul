PRAGMA writable_schema=on;

CREATE TABLE keys_v11 (
        id INTEGER NOT NULL,
        name TEXT NOT NULL, 
        keytype VARCHAR(5) NOT NULL,
        fingerprint TEXT NOT NULL, 
        PRIMARY KEY (id),
        UNIQUE (name), 
        CONSTRAINT keytypeenum CHECK (keytype IN ('gnupg', 'ECC')),
        UNIQUE (fingerprint)
);

INSERT INTO keys_v11 SELECT id,name,"gnupg",fingerprint FROM keys;

ALTER TABLE keys RENAME TO keys_v10;
ALTER TABLE keys_v11 RENAME TO keys;

PRAGMA writable_schema=off;

PRAGMA foreign_key_check;
PRAGMA integrity_check;

