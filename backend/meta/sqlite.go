// Copyright 2025 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package meta

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"database/sql"
	_ "github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/embed"
)

// SqliteCar is a metadata storer that uses an sqlite database per bucket to store metadata.
type SqliteCar struct {
	dir string
	mu   sync.Mutex
	dbs  map[string]*sql.DB
}

// NewSqliteCar creates a new SqliteCar metadata storer.
func NewSqliteCar(dir string) (SqliteCar, error) {
	fi, err := os.Lstat(dir)
	if err != nil {
		return SqliteCar{}, fmt.Errorf("failed to stat directory: %v", err)
	}
	if !fi.IsDir() {
		return SqliteCar{}, fmt.Errorf("not a directory")
	}

	return SqliteCar{dir: dir, dbs: make(map[string]*sql.DB)}, nil
}

// getDB returns (and lazily creates) the shared DB connection for the bucket.
func (s *SqliteCar) getDB(bucket string) (*sql.DB, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Already opened?
	if db, ok := s.dbs[bucket]; ok {
		return db, nil
	}

	// Create a new shared DB connection
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(s.dir, bucket))
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	// Ensure table exists
	createTable := `
	CREATE TABLE IF NOT EXISTS attributes (
		object TEXT NOT NULL,
		attribute TEXT NOT NULL,
		value BLOB,
		PRIMARY KEY (object, attribute)
	);`
	if _, err := db.Exec(createTable); err != nil {
		db.Close()
		return nil, fmt.Errorf("create table: %w", err)
	}

	s.dbs[bucket] = db
	return db, nil
}

// RetrieveAttribute retrieves the value of a specific attribute for an object or a bucket.
func (s SqliteCar) RetrieveAttribute(_ *os.File, bucket, object, attribute string) ([]byte, error) {
	db, err := s.getDB(bucket)
	if err != nil {
		return nil, err
	}

	query := `
	SELECT value
	FROM attributes
	WHERE object = ? AND attribute = ?;
	`

	var value []byte
	err = db.QueryRow(query, object, attribute).Scan(&value)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNoSuchKey // not found, but not an error
		}
		return nil, fmt.Errorf("query attribute: %w", err)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to read attribute: %v", err)
	}

	return value, nil
}

// StoreAttribute stores the value of a specific attribute for an object or a bucket.
func (s SqliteCar) StoreAttribute(_ *os.File, bucket, object, attribute string, value []byte) error {
	//Open database
	db, err := s.getDB(bucket)
	if err != nil {
		return err
	}

	insert := `
	INSERT INTO attributes (object, attribute, value)
	VALUES (?, ?, ?)
	ON CONFLICT(object, attribute) DO UPDATE SET value = excluded.value;
	`

	if _, err := db.Exec(insert, object, attribute, value); err != nil {
		return fmt.Errorf("insert attribute: %w", err)
	}

	return nil
}

// DeleteAttribute removes the value of a specific attribute for an object or a bucket.
func (s SqliteCar) DeleteAttribute(bucket, object, attribute string) error {
	db, err := s.getDB(bucket)
	if err != nil {
		return err
	}

	deleteStmt := `
	DELETE FROM attributes
	WHERE object = ? AND attribute = ?;
	`

	if _, err := db.Exec(deleteStmt, object, attribute); err != nil {
		return fmt.Errorf("delete attribute: %w", err)
	}

	return nil
}

// ListAttributes lists all attributes for an object or a bucket.
func (s SqliteCar) ListAttributes(bucket, object string) ([]string, error) {
	db, err := s.getDB(bucket)
	if err != nil {
		return nil, err
	}

	query := `
	SELECT attribute
	FROM attributes
	WHERE object = ?
	ORDER BY attribute;
	`

	rows, err := db.Query(query, object)
	if err != nil {
		return nil, fmt.Errorf("list attributes: %w", err)
	}
	defer rows.Close()

	var attrs []string
	for rows.Next() {
		var attr string
		if err := rows.Scan(&attr); err != nil {
			return nil, fmt.Errorf("scan attribute: %w", err)
		}
		attrs = append(attrs, attr)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return attrs, nil

}

// DeleteAttributes removes all attributes for an object or a bucket.
func (s SqliteCar) DeleteAttributes(bucket, object string) error {

	db, err := s.getDB(bucket)
	if err != nil {
		return err
	}

	deleteStmt := `
	DELETE FROM attributes
	WHERE object = ?;
	`

	if _, err := db.Exec(deleteStmt, object); err != nil {
		return fmt.Errorf("delete attributes: %w", err)
	}

	return nil

}
