CREATE TABLE IF NOT EXISTS omega_storage_format (
    singleton TINYINT UNSIGNED NOT NULL PRIMARY KEY CHECK (singleton=1),
    format_name VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL
);
