use crate::{schema_objects, sql_error, validate_schema, Error};
use rusqlite::{Connection, Transaction, TransactionBehavior};

/// An exact v1 history was rebuilt under the v2 schema without adding a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaMigration {
    pub rows: u64,
}

impl std::fmt::Display for SchemaMigration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "aura schema v1 to v2, {} rows", self.rows)
    }
}

const COLUMNS: &str = "seq,prev,hash,sig,at,kind,actor,op,phase,body";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Copied,
    Restored,
}

pub(crate) fn migrate_v1(connection: &Connection) -> Result<Option<SchemaMigration>, Error> {
    migrate_with(connection, |_, _| Ok(()))
}

fn migrate_with(
    connection: &Connection,
    checkpoint: impl Fn(Stage, &Connection) -> Result<(), Error>,
) -> Result<Option<SchemaMigration>, Error> {
    let v1 = Connection::open_in_memory().map_err(sql_error)?;
    v1.execute_batch(include_str!("schema_v1.sql"))
        .map_err(sql_error)?;
    let expected_v1 = schema_objects(&v1, "main")?;
    if schema_objects(connection, "main")? != expected_v1 {
        return Ok(None);
    }
    if !schema_objects(connection, "temp")?.is_empty() {
        return Err(Error::new("aura:temp-schema-mismatch"));
    }

    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Immediate)
        .map_err(sql_error)?;
    // Another initializer may have committed while this connection waited.
    if schema_objects(&transaction, "main")? != expected_v1 {
        validate_schema(&transaction)?;
        transaction.rollback().map_err(sql_error)?;
        return Ok(None);
    }
    let rows: i64 = transaction
        .query_row("SELECT count(*) FROM main.aura", [], |row| row.get(0))
        .map_err(sql_error)?;
    transaction
        .execute_batch(&format!(
            "CREATE TEMP TABLE aura_migration_v1 AS SELECT {COLUMNS} FROM main.aura"
        ))
        .map_err(sql_error)?;
    checkpoint(Stage::Copied, &transaction)?;
    compare_copy(&transaction, rows)?;

    // No admitted schema object can have an incoming Aura foreign key.
    // DROP removes v1's indexes and triggers; exact v2 statements recreate them.
    transaction
        .execute_batch("DROP TABLE main.aura")
        .map_err(sql_error)?;
    transaction
        .execute_batch(include_str!("schema.sql"))
        .map_err(sql_error)?;
    transaction
        .execute_batch(&format!(
            "INSERT INTO main.aura({COLUMNS}) SELECT {COLUMNS} FROM temp.aura_migration_v1 ORDER BY seq"
        ))
        .map_err(sql_error)?;
    checkpoint(Stage::Restored, &transaction)?;
    compare_copy(&transaction, rows)?;
    transaction
        .execute_batch("DROP TABLE temp.aura_migration_v1")
        .map_err(sql_error)?;
    validate_schema(&transaction)?;
    transaction.commit().map_err(sql_error)?;
    Ok(Some(SchemaMigration { rows: rows as u64 }))
}

fn compare_copy(connection: &Connection, expected_rows: i64) -> Result<(), Error> {
    let (source_rows, copied_rows): (i64, i64) = connection
        .query_row(
            "SELECT (SELECT count(*) FROM main.aura), (SELECT count(*) FROM temp.aura_migration_v1)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sql_error)?;
    if expected_rows != source_rows || expected_rows != copied_rows {
        return Err(Error::new("aura:migration-mismatch"));
    }
    // BLOB comparisons preserve bytes; typeof also preserves storage classes.
    let differences = COLUMNS
        .split(',')
        .map(|column| {
            format!("typeof(old.{column}) != typeof(new.{column}) OR CAST(old.{column} AS BLOB) IS NOT CAST(new.{column} AS BLOB)")
        })
        .collect::<Vec<_>>()
        .join(" OR ");
    let differs: bool = connection
        .query_row(
            &format!(
                "SELECT EXISTS(SELECT 1 FROM temp.aura_migration_v1 AS old LEFT JOIN main.aura AS new ON old.seq=new.seq WHERE {differences}) OR EXISTS(SELECT 1 FROM main.aura AS new LEFT JOIN temp.aura_migration_v1 AS old ON old.seq=new.seq WHERE {differences})"
            ),
            [],
            |row| row.get(0),
        )
        .map_err(sql_error)?;
    if differs {
        return Err(Error::new("aura:migration-mismatch"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
    use rusqlite::types::Value;

    fn fixture() -> (tempfile::TempDir, Connection) {
        let directory = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let connection = Connection::open(directory.path().join("migration.db")).unwrap();
        connection
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL")
            .unwrap();
        connection
            .execute_batch(include_str!("schema_v1.sql"))
            .unwrap();
        for sequence in 1..=3 {
            let previous = if sequence == 1 {
                crate::DOMAIN.to_owned()
            } else {
                format!("{:064x}", sequence - 1)
            };
            connection.execute("INSERT INTO aura VALUES(?1,?2,?3,'signature',7,'boot.facts','actor','','fact','{}')", rusqlite::params![sequence, previous, format!("{sequence:064x}")]).unwrap();
        }
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        (directory, connection)
    }

    fn rows(connection: &Connection) -> Vec<Vec<Value>> {
        connection
            .prepare(&format!("SELECT {COLUMNS} FROM main.aura ORDER BY seq"))
            .unwrap()
            .query_map([], |row| (0..10).map(|index| row.get(index)).collect())
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn assert_rollback(
        directory: &tempfile::TempDir,
        connection: &Connection,
        checkpoint: impl Fn(Stage, &Connection) -> Result<(), Error>,
        code: &str,
    ) {
        let before_schema = schema_objects(connection, "main").unwrap();
        let before_rows = rows(connection);
        let path = directory.path().join("migration.db");
        let before_bytes = std::fs::read(&path).unwrap();
        assert_eq!(migrate_with(connection, checkpoint).unwrap_err().code, code);
        assert!(connection.is_autocommit());
        assert_eq!(schema_objects(connection, "main").unwrap(), before_schema);
        assert_eq!(rows(connection), before_rows);
        assert_eq!(std::fs::read(&path).unwrap(), before_bytes);
        let leftovers: i64 = connection
            .query_row(
                "SELECT count(*) FROM temp.sqlite_schema WHERE name='aura_migration_v1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(leftovers, 0);
        let reopened = Connection::open(path).unwrap();
        assert_eq!(rows(&reopened), before_rows);
        assert_eq!(
            crate::initialize_with_report(&reopened).unwrap(),
            Some(SchemaMigration { rows: 3 })
        );
    }

    #[test]
    fn antibody_aura_migration_failure_rolls_back_schema_rows_and_file() {
        for fail_at in [Stage::Copied, Stage::Restored] {
            let (directory, connection) = fixture();
            assert_rollback(
                &directory,
                &connection,
                |stage, _| {
                    if stage == fail_at {
                        Err(Error::new("aura:migration-injected"))
                    } else {
                        Ok(())
                    }
                },
                "aura:migration-injected",
            );
        }
    }

    #[test]
    fn antibody_aura_migration_compares_every_column_before_drop_and_commit() {
        for stage_to_change in [Stage::Copied, Stage::Restored] {
            for assignment in [
                "seq=seq+10",
                "prev='different'",
                "hash='different'",
                "sig='different'",
                "at=at+1",
                "kind='gate.apply'",
                "actor='different'",
                "op='different'",
                "phase='intent'",
                "body='{\"different\":true}'",
                "sig=CAST(sig AS BLOB)",
                "actor=actor || char(0)",
            ] {
                let (directory, connection) = fixture();
                assert_rollback(
                    &directory,
                    &connection,
                    |stage, transaction| {
                        if stage == stage_to_change {
                            transaction
                                .execute_batch(&format!(
                                    "UPDATE temp.aura_migration_v1 SET {assignment} WHERE seq=2"
                                ))
                                .map_err(sql_error)?;
                        }
                        Ok(())
                    },
                    "aura:migration-mismatch",
                );
            }
        }
    }

    #[test]
    fn antibody_aura_migration_compares_counts_and_both_directions() {
        for damage in [
            "INSERT INTO temp.aura_migration_v1 SELECT * FROM temp.aura_migration_v1 WHERE seq=1",
            "DELETE FROM temp.aura_migration_v1 WHERE seq=2",
            "DELETE FROM temp.aura_migration_v1 WHERE seq=2; INSERT INTO temp.aura_migration_v1 SELECT * FROM temp.aura_migration_v1 WHERE seq=1",
        ] {
            let (directory, connection) = fixture();
            assert_rollback(
                &directory,
                &connection,
                |stage, transaction| {
                    if matches!(stage, Stage::Restored) {
                        transaction.execute_batch(damage).map_err(sql_error)?;
                    }
                    Ok(())
                },
                "aura:migration-mismatch",
            );
        }
    }

    #[test]
    fn antibody_aura_migration_validates_v2_before_commit() {
        let (directory, connection) = fixture();
        assert_rollback(
            &directory,
            &connection,
            |stage, transaction| {
                if matches!(stage, Stage::Restored) {
                    transaction
                        .execute_batch("CREATE INDEX extra ON aura(actor)")
                        .map_err(sql_error)?;
                }
                Ok(())
            },
            "aura:schema-mismatch",
        );
    }

    #[test]
    fn antibody_aura_migration_holds_immediate_write_lock_before_copy() {
        let (directory, connection) = fixture();
        let peer = Connection::open(directory.path().join("migration.db")).unwrap();
        peer.busy_timeout(std::time::Duration::ZERO).unwrap();
        let report = migrate_with(&connection, |stage, _| {
            if matches!(stage, Stage::Copied) {
                assert_eq!(
                    peer.execute_batch("BEGIN IMMEDIATE")
                        .unwrap_err()
                        .sqlite_error_code(),
                    Some(rusqlite::ErrorCode::DatabaseBusy)
                );
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(report, Some(SchemaMigration { rows: 3 }));
    }

    #[test]
    fn antibody_aura_migration_restores_in_sequence_order() {
        let (_directory, connection) = fixture();
        let before = rows(&connection);
        let report = migrate_with(&connection, |stage, transaction| {
            if matches!(stage, Stage::Copied) {
                transaction
                    .execute_batch(
                        "CREATE TEMP TABLE reversed AS SELECT * FROM temp.aura_migration_v1 ORDER BY seq DESC;
                         DELETE FROM temp.aura_migration_v1;
                         INSERT INTO temp.aura_migration_v1 SELECT * FROM temp.reversed;
                         DROP TABLE temp.reversed;",
                    )
                    .map_err(sql_error)?;
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(report, Some(SchemaMigration { rows: 3 }));
        assert_eq!(rows(&connection), before);
        validate_schema(&connection).unwrap();
    }

    #[test]
    fn antibody_aura_migration_rechecks_schema_under_write_lock() {
        for peer_migrates in [false, true] {
            let (directory, connection) = fixture();
            let path = directory.path().join("migration.db");
            let mut once = true;
            connection
                .authorizer(Some(move |context: AuthContext<'_>| {
                    if once
                        && matches!(
                            context.action,
                            AuthAction::Transaction {
                                operation: TransactionOperation::Begin
                            }
                        )
                    {
                        once = false;
                        let peer = Connection::open(&path).unwrap();
                        if peer_migrates {
                            assert_eq!(
                                crate::initialize_with_report(&peer).unwrap(),
                                Some(SchemaMigration { rows: 3 })
                            );
                        } else {
                            peer.execute_batch("CREATE INDEX extra ON aura(actor)")
                                .unwrap();
                        }
                    }
                    Authorization::Allow
                }))
                .unwrap();
            let result = migrate_v1(&connection);
            if peer_migrates {
                assert_eq!(result.unwrap(), None);
                validate_schema(&connection).unwrap();
            } else {
                assert_eq!(result.unwrap_err().code, "aura:schema-mismatch");
                let expected = Connection::open_in_memory().unwrap();
                expected
                    .execute_batch(include_str!("schema_v1.sql"))
                    .unwrap();
                expected
                    .execute_batch("CREATE INDEX extra ON aura(actor)")
                    .unwrap();
                assert_eq!(
                    schema_objects(&connection, "main").unwrap(),
                    schema_objects(&expected, "main").unwrap()
                );
            }
        }
    }
}
