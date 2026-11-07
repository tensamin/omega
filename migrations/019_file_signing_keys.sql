-- Public cryptographic evidence is separate from mutable profile data.
CREATE TABLE omega_file_signing_keys (
    user_id BIGINT NOT NULL,
    key_id CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    public_key MEDIUMBLOB NOT NULL,
    PRIMARY KEY (user_id, key_id)
);

INSERT INTO omega_file_signing_keys (user_id, key_id, public_key)
SELECT id, LOWER(SHA2(public_key, 256)), public_key FROM users;
