// Package db provides database management for the Shepherd project's firewall and billing data
package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"
)

type FirewallManager struct {
	dbPath string
	db     *sql.DB
}

func NewFirewallManager(dbPath string) (*FirewallManager, error) {
	mgr := &FirewallManager{dbPath: dbPath}
	if err := mgr.Initialize(); err != nil {
		return nil, err
	}
	return mgr, nil
}

func (m *FirewallManager) Initialize() error {
	_, err := os.Stat(m.dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Creating new firewall database at %s", m.dbPath)
		} else {
			return err
		}
	} else {
		log.Printf("Using existing firewall database at %s", m.dbPath)
	}

	db, err := sql.Open("sqlite3", m.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return fmt.Errorf("failed to ping database: %w", err)
	}

	m.db = db
	if err := m.InitTables(); err != nil {
		m.Close()
		return fmt.Errorf("failed to init tables: %w", err)
	}

	return nil
}

func (m *FirewallManager) InitTables() error {
	_, err := m.db.Exec(`
        CREATE TABLE IF NOT EXISTS firewall_rules (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            source TEXT NOT NULL,
            destination TEXT NOT NULL,
            action TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `)
	if err != nil {
		return fmt.Errorf("failed to create firewall_rules table: %w", err)
	}

	_, err = m.db.Exec(`
        CREATE TABLE IF NOT EXISTS paywall_clients (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            plan TEXT NOT NULL,
            amount REAL NOT NULL,
            status TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `)
	if err != nil {
		return fmt.Errorf("failed to create paywall_clients table: %w", err)
	}

	_, err = m.db.Exec(`
        CREATE TABLE IF NOT EXISTS billing_transactions (
            id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            amount REAL NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (client_id) REFERENCES paywall_clients (id)
        )
    `)
	if err != nil {
		return fmt.Errorf("failed to create billing_transactions table: %w", err)
	}

	return nil
}

func (m *FirewallManager) Close() error {
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}

func (m *FirewallManager) GetDB() *sql.DB {
	return m.db
}
