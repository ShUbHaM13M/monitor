-- Inbound webhook monitors are checks with kind = 'webhook'. Optional signature
-- verification; the shared secret is sealed with SECRET_KEY like channel configs.
ALTER TABLE checks
    ADD COLUMN signature_scheme   text CHECK (signature_scheme IN ('stripe', 'github', 'shopify', 'hmac_sha256')),
    -- Header carrying the signature, for the generic scheme.
    ADD COLUMN signature_header   text,
    ADD COLUMN signing_secret_enc bytea,
    ADD CONSTRAINT checks_signature_check CHECK (
        (signature_scheme IS NULL AND signing_secret_enc IS NULL AND signature_header IS NULL)
     OR (signature_scheme IS NOT NULL AND kind = 'webhook' AND signing_secret_enc IS NOT NULL
         AND (signature_scheme <> 'hmac_sha256' OR signature_header IS NOT NULL))
    );

-- Deliveries are logged as pings: 'webhook' when accepted, 'rejected' when the
-- signature didn't verify (with the reason in `note`).
ALTER TABLE pings DROP CONSTRAINT pings_kind_check;
ALTER TABLE pings ADD CONSTRAINT pings_kind_check
    CHECK (kind IN ('start', 'success', 'fail', 'exit', 'webhook', 'rejected'));
ALTER TABLE pings
    -- Request headers (sensitive ones redacted), for the delivery viewer.
    ADD COLUMN headers jsonb,
    ADD COLUMN method text,
    -- Webhook payloads keep their *start* (JSON reads top-down); this marks a cut.
    ADD COLUMN body_truncated boolean NOT NULL DEFAULT false,
    ADD COLUMN note text;
