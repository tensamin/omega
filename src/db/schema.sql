CREATE TABLE IF NOT EXISTS iotas (
    id BIGINT NOT NULL PRIMARY KEY,
    public_key BLOB NOT NULL,
    public_key_hash BINARY(32) NOT NULL,
    node_id VARCHAR(80) CHARACTER SET ascii COLLATE ascii_bin NULL,
    node_descriptor LONGTEXT NULL,
    node_descriptor_revision BIGINT NULL,
    node_descriptor_valid_until BIGINT NULL,
    UNIQUE KEY uk_iotas_public_key_hash (public_key_hash),
    UNIQUE KEY uk_iotas_node_id (node_id)
);

CREATE TABLE IF NOT EXISTS iota_key_authority (
    public_key_hash BINARY(32) NOT NULL PRIMARY KEY,
    revoked_at TIMESTAMP(3) NULL
);

CREATE TABLE IF NOT EXISTS users (
    id BIGINT NOT NULL PRIMARY KEY,
    iota_id BIGINT NULL,
    username VARBINARY(255) NOT NULL,
    display VARBINARY(255),
    status VARBINARY(255),
    about VARBINARY(1000),
    avatar BLOB,
    sub_level INT NOT NULL DEFAULT 0,
    sub_end BIGINT NOT NULL DEFAULT 0,
    public_key BLOB NOT NULL,
    token BLOB NOT NULL,
    created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    presence_preference VARBINARY(32) NOT NULL DEFAULT 'user_online',
    UNIQUE KEY uk_users_username (username),
    KEY idx_users_iota_id (iota_id),
    CONSTRAINT fk_users_iota FOREIGN KEY (iota_id) REFERENCES iotas (id) ON DELETE SET NULL,
    CONSTRAINT chk_users_presence_preference CHECK (presence_preference IN (
        'user_online', 'user_idle', 'user_dnd', 'user_wc', 'user_invisible'
    ))
);

CREATE TABLE IF NOT EXISTS omikrons (
    id BIGINT NOT NULL PRIMARY KEY,
    public_key BLOB NOT NULL,
    location VARBINARY(255) NOT NULL,
    ip_address VARBINARY(45) NOT NULL,
    port INT NOT NULL
);

CREATE TABLE IF NOT EXISTS notifications (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    sender_id BIGINT NOT NULL,
    receiver_id BIGINT NOT NULL,
    amount BIGINT NOT NULL DEFAULT 1,
    UNIQUE KEY uk_notifications_sender_receiver (sender_id, receiver_id),
    INDEX idx_notifications_receiver (receiver_id)
);

CREATE TABLE IF NOT EXISTS registration_leases (
    token CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    user_id BIGINT NOT NULL UNIQUE,
    iota_id BIGINT NOT NULL,
    expires_at DATETIME NOT NULL,
    completed_at DATETIME NULL,
    request_id INT UNSIGNED NULL,
    request_token BINARY(16) NULL,
    CONSTRAINT fk_registration_leases_iota FOREIGN KEY (iota_id) REFERENCES iotas (id),
    CONSTRAINT uk_registration_leases_iota_request UNIQUE (iota_id, request_id),
    CONSTRAINT uk_registration_leases_iota_token UNIQUE (iota_id, request_token),
    INDEX idx_registration_leases_expiry (expires_at)
);

CREATE TABLE IF NOT EXISTS pending_iota_user_erasure (
    user_id BIGINT NOT NULL,
    iota_id BIGINT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, iota_id),
    CONSTRAINT fk_pending_iota_user_erasure_iota FOREIGN KEY (iota_id) REFERENCES iotas (id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS iota_snapshot_outbox (
    iota_id BIGINT NOT NULL PRIMARY KEY,
    updated_at DATETIME NOT NULL,
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS user_invitations (
    invitation_id BIGINT NOT NULL PRIMARY KEY,
    token_hash BINARY(32) NOT NULL,
    short_token_hash BINARY(32) NULL,
    password_hash VARBINARY(255) NULL,
    iota_id BIGINT NOT NULL,
    label VARBINARY(255) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    state ENUM('pending', 'provisioning', 'redeemed', 'revoked', 'expired') NOT NULL DEFAULT 'pending',
    revision BIGINT NOT NULL DEFAULT 1,
    redeemed_user_id BIGINT NULL,
    redeemed_at TIMESTAMP NULL,
    revoked_at TIMESTAMP NULL,
    KEY idx_user_invitations_target_state (iota_id, state),
    CONSTRAINT fk_user_invitations_iota FOREIGN KEY (iota_id) REFERENCES iotas (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS pending_iota_user_provisioning (
    user_id BIGINT NOT NULL,
    iota_id BIGINT NOT NULL,
    invitation_id BIGINT NOT NULL,
    username VARBINARY(255) NOT NULL,
    public_key BLOB NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, iota_id),
    CONSTRAINT fk_pending_iota_user_provisioning_iota FOREIGN KEY (iota_id) REFERENCES iotas (id) ON DELETE RESTRICT,
    CONSTRAINT fk_pending_iota_user_provisioning_invitation FOREIGN KEY (invitation_id) REFERENCES user_invitations (invitation_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS direct_link_keys (
    key_hash BINARY(32) NOT NULL PRIMARY KEY,
    target_kind ENUM('url', 'invitation') NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_direct_link_keys_created_at (created_at)
);

CREATE TABLE IF NOT EXISTS short_links (
    key_hash BINARY(32) NOT NULL PRIMARY KEY,
    long_url TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    creator_omikron_id BIGINT NULL,
    INDEX idx_short_links_created_at (created_at),
    INDEX idx_short_links_creator (creator_omikron_id),
    CONSTRAINT fk_short_links_direct_key FOREIGN KEY (key_hash) REFERENCES direct_link_keys (key_hash) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS invitation_short_links (
    key_hash BINARY(32) NOT NULL PRIMARY KEY,
    invitation_id BIGINT NOT NULL UNIQUE,
    CONSTRAINT fk_invitation_short_links_direct_key FOREIGN KEY (key_hash) REFERENCES direct_link_keys (key_hash) ON DELETE CASCADE,
    CONSTRAINT fk_invitation_short_links_invitation FOREIGN KEY (invitation_id) REFERENCES user_invitations (invitation_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS omega_principal_descriptors (
    user_id BIGINT NOT NULL PRIMARY KEY,
    source_hash BINARY(32) NOT NULL,
    revision BIGINT NOT NULL,
    issued_at BIGINT NOT NULL,
    valid_until BIGINT NULL,
    CONSTRAINT fk_omega_principal_descriptors_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS omega_file_signing_keys (
    user_id BIGINT NOT NULL,
    key_id CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    public_key MEDIUMBLOB NOT NULL,
    PRIMARY KEY (user_id, key_id)
);
