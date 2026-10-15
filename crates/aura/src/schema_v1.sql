CREATE TABLE IF NOT EXISTS aura (
    seq INTEGER PRIMARY KEY CHECK(seq BETWEEN 1 AND 9007199254740991),
    prev TEXT NOT NULL,
    hash TEXT NOT NULL UNIQUE CHECK(length(hash)=64 AND hash NOT GLOB '*[^0-9a-f]*'),
    sig TEXT NOT NULL,
    at INTEGER NOT NULL CHECK(typeof(at)='integer' AND at BETWEEN -9007199254740991 AND 9007199254740991),
    kind TEXT NOT NULL CHECK(kind IN (
        'boot.facts','gate.propose','gate.review','gate.consume','gate.apply',
        'gate.retire','gate.refuse','gate.expire','gate.recover','floor.advance',
        'aumlok.enrol','aumlok.bind','aumlok.signin','broker.grant','broker.reserve',
        'broker.settle','broker.revoke','kira.save','kira.demote','kira.permission',
        'sandbox.start','sandbox.exit'
    )),
    actor TEXT NOT NULL,
    op TEXT NOT NULL,
    phase TEXT NOT NULL CHECK(phase IN ('intent','settle','terminal','fact')),
    body TEXT NOT NULL,
    CHECK(phase != 'terminal' OR op != '')
);
CREATE UNIQUE INDEX IF NOT EXISTS aura_one_terminal ON aura(op) WHERE phase='terminal';
CREATE TRIGGER IF NOT EXISTS aura_no_update BEFORE UPDATE ON aura BEGIN
    SELECT RAISE(ABORT, 'aura:update-forbidden');
END;
CREATE TRIGGER IF NOT EXISTS aura_no_delete BEFORE DELETE ON aura BEGIN
    SELECT RAISE(ABORT, 'aura:delete-forbidden');
END;
CREATE TRIGGER IF NOT EXISTS aura_next_sequence BEFORE INSERT ON aura BEGIN
    SELECT CASE WHEN NEW.seq != coalesce((SELECT max(seq)+1 FROM aura),1)
        THEN RAISE(ABORT, 'aura:sequence-gap') END;
    SELECT CASE WHEN NEW.prev != coalesce((SELECT hash FROM aura ORDER BY seq DESC LIMIT 1),'aukora:aura-record:v1')
        THEN RAISE(ABORT, 'aura:broken-link') END;
    SELECT CASE WHEN EXISTS(SELECT 1 FROM aura WHERE hash=NEW.hash)
        THEN RAISE(ABORT, 'aura:duplicate-hash') END;
    SELECT CASE WHEN NEW.phase='terminal' AND EXISTS(SELECT 1 FROM aura WHERE op=NEW.op AND phase='terminal')
        THEN RAISE(ABORT, 'aura:duplicate-terminal') END;
END;
