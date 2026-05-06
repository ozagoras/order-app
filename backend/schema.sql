-- ============================================================
-- Supabase SQL Schema
-- NFC Beach Bar Ordering System
-- ============================================================
-- Run this in: Supabase dashboard → SQL Editor → New query
-- ============================================================


-- ------------------------------------------------------------
-- nfc_tags
-- Maps each physical NFC chip (by UID) to a table in the bar.
-- Also tracks the last seen counter for replay protection.
-- ------------------------------------------------------------

create table if not exists nfc_tags (
  uid           text    primary key,        -- e.g. "04A1B2C3D4E5F6"  (7 bytes hex, uppercase)
  table_id      text    not null,           -- e.g. "Table-7" or "Beach-A3"
  last_counter  integer not null default 0  -- last valid counter seen — used for replay protection
);

-- Index for fast UID lookups on every scan
create index if not exists nfc_tags_uid_idx on nfc_tags (uid);


-- ------------------------------------------------------------
-- sessions
-- Single-use sessions created on every valid NFC tap.
-- Each session is tied to one tap and can only be consumed once.
-- ------------------------------------------------------------

create table if not exists sessions (
  id          uuid        primary key default gen_random_uuid(),
  uid         text        not null,           -- which chip generated this session
  table_id    text        not null,           -- which table (denormalised for fast access)
  counter     integer     not null,           -- the ctr value from this specific tap
  used        boolean     not null default false,
  expires_at  timestamptz not null,           -- now() + 5 minutes, set by Flask
  created_at  timestamptz not null default now()
);

-- Index for fast session lookups by ID
create index if not exists sessions_id_idx on sessions (id);

-- Optional: auto-delete expired sessions after 1 hour to keep the table clean
-- (Supabase does not have built-in TTL, but you can run this manually or via a cron)
-- delete from sessions where expires_at < now() - interval '1 hour';


-- ------------------------------------------------------------
-- Row Level Security (RLS)
-- ------------------------------------------------------------
-- Enable RLS on both tables.
-- The Flask backend uses the service role key which bypasses RLS entirely,
-- so these policies only affect client-side access (which we block completely).

alter table nfc_tags enable row level security;
alter table sessions  enable row level security;

-- Block all direct client access — Flask backend handles everything
-- No policies needed because service role key bypasses RLS.
-- This just ensures no anon/authenticated client can read these tables directly.
