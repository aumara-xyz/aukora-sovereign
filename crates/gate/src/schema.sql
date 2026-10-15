PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS gate_owner(singleton INTEGER PRIMARY KEY CHECK(singleton=1),node TEXT NOT NULL,
    owner_text TEXT NOT NULL,epoch INTEGER NOT NULL CHECK(epoch>0),credential_id TEXT NOT NULL,
    sign_count INTEGER NOT NULL CHECK(sign_count>=0 AND sign_count<=4294967295));
CREATE TRIGGER IF NOT EXISTS gate_owner_retained BEFORE DELETE ON gate_owner
    BEGIN SELECT RAISE(ABORT,'gate:owner-retained'); END;
DROP TRIGGER IF EXISTS gate_owner_monotonic;
CREATE TRIGGER gate_owner_monotonic BEFORE UPDATE ON gate_owner
    WHEN NEW.node!=OLD.node OR NEW.epoch<OLD.epoch
    OR ((NEW.owner_text!=OLD.owner_text OR NEW.credential_id!=OLD.credential_id) AND NEW.epoch<=OLD.epoch)
    OR (NEW.credential_id=OLD.credential_id AND NEW.sign_count<OLD.sign_count)
    BEGIN SELECT RAISE(ABORT,'gate:owner-monotonic'); END;
CREATE TABLE IF NOT EXISTS gate_budget(singleton INTEGER PRIMARY KEY CHECK(singleton=1),window_start INTEGER NOT NULL CHECK(window_start>=0),used INTEGER NOT NULL CHECK(used>=0));
CREATE TABLE IF NOT EXISTS gate_blobs(sha256 TEXT PRIMARY KEY,bytes BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS gate_proposals(id TEXT PRIMARY KEY,target TEXT NOT NULL,base_sha256 TEXT NOT NULL,new_sha256 TEXT NOT NULL,
    digest TEXT NOT NULL,idempotency_key TEXT NOT NULL,note TEXT NOT NULL,cell TEXT NOT NULL,created INTEGER NOT NULL,expires_at INTEGER NOT NULL,updated INTEGER NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending','applying','applied','incomplete','failed','conflict','refused','expired','retired')),
    reviewed INTEGER NOT NULL DEFAULT 0 CHECK(reviewed IN (0,1)),operator_only INTEGER NOT NULL CHECK(operator_only IN (0,1)),
    write_claimed INTEGER NOT NULL DEFAULT 0 CHECK(write_claimed IN (0,1)),UNIQUE(operator_only,idempotency_key));
CREATE TRIGGER IF NOT EXISTS gate_proposals_retained BEFORE DELETE ON gate_proposals
    BEGIN SELECT RAISE(ABORT,'gate:proposal-retained'); END;
CREATE TRIGGER IF NOT EXISTS gate_proposals_facts BEFORE UPDATE ON gate_proposals
    WHEN NEW.id!=OLD.id OR NEW.target!=OLD.target OR NEW.base_sha256!=OLD.base_sha256 OR NEW.new_sha256!=OLD.new_sha256
    OR NEW.digest!=OLD.digest OR NEW.idempotency_key!=OLD.idempotency_key OR NEW.note!=OLD.note OR NEW.cell!=OLD.cell
    OR NEW.created!=OLD.created OR NEW.expires_at!=OLD.expires_at OR NEW.operator_only!=OLD.operator_only OR NEW.reviewed<OLD.reviewed
    OR NEW.write_claimed<OLD.write_claimed OR (NEW.write_claimed>OLD.write_claimed AND OLD.state!='applying')
    OR (OLD.state='pending' AND NEW.state NOT IN ('pending','applying','refused','expired','retired','incomplete'))
    OR (OLD.state!='pending' AND NOT (OLD.state='applying' AND (NEW.state IN ('applied','incomplete','failed','conflict') OR (NEW.state='applying' AND NEW.write_claimed>OLD.write_claimed))))
    BEGIN SELECT RAISE(ABORT,'gate:proposal-final'); END;
CREATE TABLE IF NOT EXISTS gate_reviews(challenge TEXT PRIMARY KEY,proposal_id TEXT NOT NULL REFERENCES gate_proposals(id),
    base_sha256 TEXT NOT NULL,new_sha256 TEXT NOT NULL,display_sha256 TEXT NOT NULL,auth BLOB NOT NULL,card BLOB NOT NULL,
    owner_text TEXT NOT NULL,issued_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,issue_seq INTEGER NOT NULL,issue_hash TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('live','spent','invalidated')));
CREATE UNIQUE INDEX IF NOT EXISTS gate_one_live_review ON gate_reviews(proposal_id) WHERE state='live';
CREATE TRIGGER IF NOT EXISTS gate_reviews_retained BEFORE DELETE ON gate_reviews
    BEGIN SELECT RAISE(ABORT,'gate:review-retained'); END;
CREATE TRIGGER IF NOT EXISTS gate_reviews_facts BEFORE UPDATE ON gate_reviews
    WHEN NEW.challenge!=OLD.challenge OR NEW.proposal_id!=OLD.proposal_id OR NEW.base_sha256!=OLD.base_sha256 OR NEW.new_sha256!=OLD.new_sha256
    OR NEW.display_sha256!=OLD.display_sha256 OR NEW.auth!=OLD.auth OR NEW.card!=OLD.card OR NEW.owner_text!=OLD.owner_text
    OR NEW.issued_at!=OLD.issued_at OR NEW.expires_at!=OLD.expires_at OR NEW.issue_seq!=OLD.issue_seq OR NEW.issue_hash!=OLD.issue_hash
    OR OLD.state!='live' OR NEW.state='live'
    BEGIN SELECT RAISE(ABORT,'gate:review-final'); END;
CREATE TABLE IF NOT EXISTS gate_burns(challenge TEXT PRIMARY KEY REFERENCES gate_reviews(challenge));
CREATE TRIGGER IF NOT EXISTS gate_burns_no_update BEFORE UPDATE ON gate_burns
    BEGIN SELECT RAISE(ABORT,'gate:burn-retained'); END;
CREATE TRIGGER IF NOT EXISTS gate_burns_no_delete BEFORE DELETE ON gate_burns
    BEGIN SELECT RAISE(ABORT,'gate:burn-retained'); END;
CREATE TABLE IF NOT EXISTS gate_consumptions(proposal_id TEXT PRIMARY KEY REFERENCES gate_proposals(id),challenge TEXT NOT NULL UNIQUE REFERENCES gate_reviews(challenge),
    auth_sha256 TEXT NOT NULL UNIQUE,proof_sha256 TEXT NOT NULL,owner_text TEXT NOT NULL,accepted_at INTEGER NOT NULL,consume_seq INTEGER NOT NULL UNIQUE,consume_hash TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS gate_consumptions_no_update BEFORE UPDATE ON gate_consumptions
    BEGIN SELECT RAISE(ABORT,'gate:consumption-retained'); END;
CREATE TRIGGER IF NOT EXISTS gate_consumptions_no_delete BEFORE DELETE ON gate_consumptions
    BEGIN SELECT RAISE(ABORT,'gate:consumption-retained'); END;
CREATE TABLE IF NOT EXISTS gate_receipts(proposal_id TEXT PRIMARY KEY REFERENCES gate_proposals(id),body TEXT NOT NULL,seq INTEGER NOT NULL UNIQUE,hash TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS gate_receipts_no_update BEFORE UPDATE ON gate_receipts
    BEGIN SELECT RAISE(ABORT,'gate:receipt-retained'); END;
CREATE TRIGGER IF NOT EXISTS gate_receipts_no_delete BEFORE DELETE ON gate_receipts
    BEGIN SELECT RAISE(ABORT,'gate:receipt-retained'); END;
CREATE TABLE IF NOT EXISTS gate_reconciliations(proposal_id TEXT PRIMARY KEY REFERENCES gate_proposals(id),
    base_sha256 TEXT NOT NULL,seq INTEGER NOT NULL UNIQUE,hash TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS gate_reconciliations_no_update BEFORE UPDATE ON gate_reconciliations
    BEGIN SELECT RAISE(ABORT,'gate:reconciliation-retained'); END;
CREATE TRIGGER IF NOT EXISTS gate_reconciliations_no_delete BEFORE DELETE ON gate_reconciliations
    BEGIN SELECT RAISE(ABORT,'gate:reconciliation-retained'); END;

CREATE TABLE IF NOT EXISTS gate_auto(proposal_id TEXT PRIMARY KEY REFERENCES gate_proposals(id),permission_id TEXT NOT NULL REFERENCES gate_proposals(id),authorization_sha256 TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS gate_auto_no_update BEFORE UPDATE ON gate_auto BEGIN SELECT RAISE(ABORT,'gate:auto-retained'); END;
CREATE TRIGGER IF NOT EXISTS gate_auto_no_delete BEFORE DELETE ON gate_auto BEGIN SELECT RAISE(ABORT,'gate:auto-retained'); END;
