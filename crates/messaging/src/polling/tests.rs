// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;

fn id(number: i64) -> EventId {
    let mut id = [0; 32];
    id[..8].copy_from_slice(&number.to_be_bytes());
    EventId::from_bytes(id)
}

fn envelope(number: i64, size: usize) -> Result<TransportEnvelope> {
    Ok(TransportEnvelope {
        v: nostr::transport::TRANSPORT_VERSION,
        codec: EnvelopeCodec::Nip59V1,
        recipient: nostr::SecretKey::import(zeroize::Zeroizing::new([1; 32]))?.public_key()?,
        id: id(number),
        bytes: vec![0; size],
    })
}

fn usage(db: &Connection) -> (i64, i64) {
    db.query_row(
        "SELECT count(*),coalesce(sum(length(bytes)),0) FROM messaging_ingress_retry",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .unwrap()
}

fn retained(db: &Connection, number: i64) -> Result<bool> {
    Ok(db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM messaging_ingress_retry WHERE envelope=?1)",
            [id(number).as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap())
}

#[test]
fn retry_ciphertext_row_budget_evicts_oldest_even_after_another_attempt() -> Result<()> {
    let db = Connection::open_in_memory().unwrap();
    initialize(&db)?;
    let seed = envelope(0, 1)?;
    for number in 0..RETRY_ENVELOPE_CAP {
        db.execute(
            "INSERT INTO messaging_ingress_retry VALUES(?1,?2,?3,0)",
            params![
                id(number).as_bytes().as_slice(),
                seed.recipient.as_bytes().as_slice(),
                &seed.bytes
            ],
        )
        .unwrap();
    }
    retain_retry(&db, &envelope(0, 1)?)?;
    retain_retry(&db, &envelope(RETRY_ENVELOPE_CAP, 1)?)?;
    assert_eq!(usage(&db), (RETRY_ENVELOPE_CAP, RETRY_ENVELOPE_CAP));
    assert!(!retained(&db, 0)?);
    assert!(retained(&db, 1)?);
    assert!(retained(&db, RETRY_ENVELOPE_CAP)?);
    Ok(())
}

#[test]
fn retry_ciphertext_byte_budget_evicts_oldest_and_bounds_existing_queues() -> Result<()> {
    let db = Connection::open_in_memory().unwrap();
    initialize(&db)?;
    let size = nostr::transport::MAX_ENVELOPE_BYTES;
    let capacity = RETRY_BYTES_CAP / size as i64;
    for number in 0..=capacity {
        retain_retry(&db, &envelope(number, size)?)?;
    }
    assert_eq!(usage(&db), (capacity, RETRY_BYTES_CAP));
    assert!(!retained(&db, 0)?);
    assert!(retained(&db, 1)?);
    assert!(retained(&db, capacity)?);

    // Older releases may already have retained more ciphertext than the budget.
    let newest = envelope(capacity + 1, size)?;
    db.execute(
        "INSERT INTO messaging_ingress_retry VALUES(?1,?2,?3,0)",
        params![
            newest.id.as_bytes().as_slice(),
            newest.recipient.as_bytes().as_slice(),
            newest.bytes
        ],
    )
    .unwrap();
    initialize(&db)?;
    assert_eq!(usage(&db), (capacity, RETRY_BYTES_CAP));
    assert!(!retained(&db, 1)?);
    assert!(retained(&db, capacity + 1)?);
    Ok(())
}
