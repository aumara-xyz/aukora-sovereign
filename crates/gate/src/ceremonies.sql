CREATE TABLE IF NOT EXISTS gate_actions(proposal_id TEXT NOT NULL REFERENCES gate_proposals(id),op TEXT NOT NULL,
 challenge TEXT PRIMARY KEY,auth BLOB NOT NULL,card BLOB NOT NULL,owner_text TEXT NOT NULL,issued INTEGER NOT NULL,
 expires INTEGER NOT NULL,current_sha256 TEXT NOT NULL,issue_seq INTEGER NOT NULL,issue_hash TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('live','spent','invalidated')));
CREATE UNIQUE INDEX IF NOT EXISTS gate_action_live ON gate_actions(proposal_id,op) WHERE state='live';
CREATE TRIGGER IF NOT EXISTS gate_actions_retained BEFORE DELETE ON gate_actions BEGIN SELECT RAISE(ABORT,'gate:action-retained'); END;
CREATE TRIGGER IF NOT EXISTS gate_actions_facts BEFORE UPDATE ON gate_actions
 WHEN NEW.proposal_id!=OLD.proposal_id OR NEW.op!=OLD.op OR NEW.challenge!=OLD.challenge OR NEW.auth!=OLD.auth OR NEW.card!=OLD.card
 OR NEW.owner_text!=OLD.owner_text OR NEW.issued!=OLD.issued OR NEW.expires!=OLD.expires OR NEW.current_sha256!=OLD.current_sha256
 OR NEW.issue_seq!=OLD.issue_seq OR NEW.issue_hash!=OLD.issue_hash OR OLD.state!='live' OR NEW.state='live'
 BEGIN SELECT RAISE(ABORT,'gate:action-final'); END;
