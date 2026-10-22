-- Public status pages: /s/{slug} shows the checks and monitors an org picks,
-- under public display names, with current status, 90-day uptime and incidents.
CREATE TABLE status_pages (
    id          uuid PRIMARY KEY,
    org_id      uuid NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    -- Global: it's the public URL.
    slug        text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{1,38}[a-z0-9])$'),
    title       text NOT NULL CHECK (length(title) BETWEEN 1 AND 100),
    description text CHECK (length(description) <= 1000),
    -- Drafts are only visible to the org.
    published   boolean NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, org_id)
);
CREATE INDEX status_pages_org_id_idx ON status_pages (org_id, created_at);

CREATE TABLE status_page_items (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    page_id      uuid NOT NULL,
    org_id       uuid NOT NULL,
    check_id     uuid,
    monitor_id   uuid,
    -- What visitors see instead of the internal name.
    display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 100),
    position     integer NOT NULL DEFAULT 0,
    -- Composite keys: a page can only show its own org's checks and monitors.
    FOREIGN KEY (page_id, org_id)    REFERENCES status_pages (id, org_id)  ON DELETE CASCADE,
    FOREIGN KEY (check_id, org_id)   REFERENCES checks (id, org_id)        ON DELETE CASCADE,
    FOREIGN KEY (monitor_id, org_id) REFERENCES http_monitors (id, org_id) ON DELETE CASCADE,
    CHECK (num_nonnulls(check_id, monitor_id) = 1),
    UNIQUE (page_id, check_id),
    UNIQUE (page_id, monitor_id)
);
CREATE INDEX status_page_items_page_idx ON status_page_items (page_id, position);
CREATE INDEX status_page_items_check_idx ON status_page_items (check_id) WHERE check_id IS NOT NULL;
CREATE INDEX status_page_items_monitor_idx ON status_page_items (monitor_id) WHERE monitor_id IS NOT NULL;

ALTER TABLE orgs ADD COLUMN max_status_pages integer CHECK (max_status_pages >= 0);
