package auditlog

import (
	"database/sql"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	_ "github.com/marcboeker/go-duckdb"
)

type DB struct {
	*sql.DB
}

func New() (*DB, error) {
	db, err := sql.Open("duckdb", "audit.db")
	if err != nil {
		return nil, err
	}

	// ignore error
	_, _ = db.Exec(`CREATE TYPE PROTOCOL AS ENUM ('tcp', 'http', 'tls');`)
	_, err = db.Exec(`CREATE SEQUENCE IF NOT EXISTS seq_log_id;`)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS log (
		id INTEGER PRIMARY KEY,
		local_addr UINTEGER,
		local_port USMALLINT,
		remote_addr UINTEGER,
		remote_port USMALLINT,
		sent_bytes LONG,
		received_bytes LONG,
		protocol PROTOCOL,
		server_name TEXT,
		created_at TIMESTAMP
	)`)
	if err != nil {
		return nil, err
	}

	return &DB{db}, nil
}

func (db *DB) Close() error {
	return db.DB.Close()
}

type Protocol string

const (
	ProtocolTCP  Protocol = "tcp"
	ProtocolHTTP Protocol = "http"
	ProtocolTLS  Protocol = "tls"
)

func (db *DB) Insert(
	src string, srcPort uint16,
	dst string, dstPort uint16,
	sentBytes uint64, receivedBytes uint64,
	protocol Protocol, serverName string,
	startTime time.Time,
) error {
	if sentBytes == 0 && receivedBytes == 0 {
		return nil
	}
	if serverName == "" {
		serverName = fmt.Sprintf("%s:%d", dst, dstPort)
	}

	tmp := net.ParseIP(src).To4()
	if tmp == nil {
		tmp = net.IPv4zero
	}
	srcIP := binary.BigEndian.Uint32(tmp)

	tmp = net.ParseIP(dst).To4()
	if tmp == nil {
		tmp = net.IPv4zero
	}
	dstIP := binary.BigEndian.Uint32(tmp)

	_, err := db.Exec(`
	INSERT INTO log (
		id, local_addr, local_port, remote_addr, remote_port,
		sent_bytes, received_bytes, protocol, server_name, created_at
	) VALUES (
		nextval('seq_log_id'), ?, ?, ?, ?, ?, ?, ?, ?, ?
	)`,
		srcIP, srcPort, dstIP, dstPort,
		sentBytes, receivedBytes, protocol, serverName, startTime,
	)
	return err
}

type AccessLog struct {
	ServerName string
	Sent       uint64
	Recv       uint64
}

func (db *DB) Query(client []net.IP, begin time.Time, count int) ([]AccessLog, error) {
	if len(client) == 0 {
		return nil, nil
	}
	stmt, err := db.Prepare(`
	SELECT server_name, SUM(sent_bytes) as sent, SUM(received_bytes) as recv FROM log
	WHERE local_addr IN ( ?` + strings.Repeat(",?", len(client)-1) + ` ) AND created_at >= ?
	GROUP BY (server_name)
	ORDER BY recv DESC
	LIMIT ?
	`)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	var args []interface{}
	for _, c := range client {
		args = append(args, binary.BigEndian.Uint32(c))
	}
	args = append(args, begin, count)
	rows, err := stmt.Query(args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []AccessLog
	for rows.Next() {
		var log AccessLog
		err = rows.Scan(&log.ServerName, &log.Sent, &log.Recv)
		if err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}
	return logs, rows.Err()
}

func (db *DB) Total(client []net.IP) (uint64, uint64, error) {
	if len(client) == 0 {
		return 0, 0, nil
	}
	stmt, err := db.Prepare(`
	SELECT SUM(sent_bytes) as sent, SUM(received_bytes) as recv FROM log
	WHERE local_addr IN ( ?` + strings.Repeat(",?", len(client)-1) + ` )
	`)
	if err != nil {
		return 0, 0, err
	}
	defer stmt.Close()

	var args []interface{}
	for _, c := range client {
		args = append(args, binary.BigEndian.Uint32(c))
	}
	rows, err := stmt.Query(args...)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()

	var sent, recv uint64
	for rows.Next() {
		err = rows.Scan(&sent, &recv)
		if err != nil {
			return 0, 0, err
		}
	}
	return sent, recv, rows.Err()
}
