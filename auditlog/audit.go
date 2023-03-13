package auditlog

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/marcboeker/go-duckdb"
)

var errFlush = errors.New("flush")

type DB struct {
	db            *sql.DB
	prepareInsert *sql.Stmt
	batch         chan<- func(*sql.Tx) error

	mu           sync.Mutex
	prepareQuery map[int]*sql.Stmt
	prepareTotal map[int]*sql.Stmt
}

func New(path string) (_ *DB, outErr error) {
	connector, err := duckdb.NewConnector(path, func(db driver.ExecerContext) error {
		// ignore error
		_, _ = db.ExecContext(context.Background(), `CREATE TYPE PROTOCOL AS ENUM ('tcp', 'http', 'tls');`, nil)

		_, err := db.ExecContext(context.Background(), `CREATE SEQUENCE IF NOT EXISTS seq_log_id;`, nil)
		if err != nil {
			return err
		}

		_, err = db.ExecContext(context.Background(), `CREATE TABLE IF NOT EXISTS log (
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
		)`, nil)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	db := sql.OpenDB(connector)
	prepareInsert, err := db.Prepare(
		`INSERT INTO log (
			id, local_addr, local_port, remote_addr, remote_port,
			sent_bytes, received_bytes, protocol, server_name, created_at
		) VALUES (
			nextval('seq_log_id'), ?, ?, ?, ?, ?, ?, ?, ?, ?
		)`,
	)
	if err != nil {
		db.Close()
		return nil, err
	}

	ch := make(chan func(*sql.Tx) error, 128)
	d := &DB{
		db:            db,
		prepareInsert: prepareInsert,
		batch:         ch,
	}
	go d.batcher(ch)
	return d, nil
}

func (db *DB) Close() error {
	return db.db.Close()
}

type Protocol string

const (
	ProtocolTCP  Protocol = "tcp"
	ProtocolHTTP Protocol = "http"
	ProtocolTLS  Protocol = "tls"
)

func (db *DB) Insert(
	src net.IP, srcPort uint16,
	dst net.IP, dstPort uint16,
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

	tmp := src.To4()
	if len(tmp) == 0 {
		tmp = net.IPv4zero
	}
	srcIP := binary.BigEndian.Uint32(tmp)

	tmp = dst.To4()
	if len(tmp) == 0 {
		tmp = net.IPv4zero
	}
	dstIP := binary.BigEndian.Uint32(tmp)

	db.batch <- func(tx *sql.Tx) error {
		_, err := tx.Stmt(db.prepareInsert).Exec(
			srcIP, srcPort, dstIP, dstPort,
			sentBytes, receivedBytes, protocol, serverName, startTime,
		)
		return err
	}
	return nil
}

type AccessLog struct {
	ServerName string
	Sent       uint64
	Recv       uint64
}

func (db *DB) doPrepareQuery(cnt int, args []interface{}) (*sql.Rows, error) {
	if cnt < 10 {
		db.mu.Lock()
		defer db.mu.Unlock()

		if db.prepareQuery == nil {
			db.prepareQuery = make(map[int]*sql.Stmt)
		}

		if s, ok := db.prepareQuery[cnt]; !ok {
			stmt, err := db.db.Prepare(
				`SELECT server_name, SUM(sent_bytes) as sent, SUM(received_bytes) as recv FROM log
				WHERE local_addr IN ( ?` + strings.Repeat(",?", cnt-1) + ` ) AND created_at >= ?
				GROUP BY (server_name)
				ORDER BY recv DESC
				LIMIT ?`,
			)
			if err != nil {
				log.Fatalln("fail to prepare query", err)
			}
			db.prepareQuery[cnt] = stmt
			return stmt.Query(args...)
		} else {
			return s.Query(args...)
		}
	}

	return db.db.Query(
		`SELECT server_name, SUM(sent_bytes) as sent, SUM(received_bytes) as recv FROM log
		WHERE local_addr IN ( ?`+strings.Repeat(",?", cnt-1)+` ) AND created_at >= ?
		GROUP BY (server_name)
		ORDER BY recv DESC
		LIMIT ?`,
		args...,
	)
}

func (db *DB) Query(client []net.IP, begin time.Time, count int) ([]AccessLog, error) {
	if len(client) == 0 {
		return nil, nil
	}

	args := make([]interface{}, 0, len(client)+2)
	for _, c := range client {
		args = append(args, binary.BigEndian.Uint32(c.To4()))
	}
	rows, err := db.doPrepareQuery(len(client), append(args, begin, count))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	logs := make([]AccessLog, 0, count)
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

func (db *DB) doPrepareTotal(cnt int, args []interface{}) *sql.Row {
	if cnt < 10 {
		db.mu.Lock()
		defer db.mu.Unlock()

		if db.prepareTotal == nil {
			db.prepareTotal = make(map[int]*sql.Stmt)
		}

		if s, ok := db.prepareTotal[cnt]; !ok {
			stmt, err := db.db.Prepare(`
				SELECT IFNULL(SUM(sent_bytes), 0) as sent, IFNULL(SUM(received_bytes), 0) as recv FROM log
				WHERE local_addr IN ( ?` + strings.Repeat(",?", cnt-1) + ` )
			`)
			if err != nil {
				log.Fatalln("fail to prepare total query", err)
			}

			db.prepareTotal[cnt] = stmt
			return stmt.QueryRow(args...)
		} else {
			return s.QueryRow(args...)
		}
	}

	return db.db.QueryRow(`
		SELECT IFNULL(SUM(sent_bytes), 0) as sent, IFNULL(SUM(received_bytes), 0) as recv FROM log
		WHERE local_addr IN ( ?`+strings.Repeat(",?", cnt-1)+` )
	`, args...)
}

func (db *DB) Total(client []net.IP) (uint64, uint64, error) {
	if len(client) == 0 {
		return 0, 0, nil
	}

	args := make([]interface{}, 0, len(client))
	for _, c := range client {
		args = append(args, binary.BigEndian.Uint32(c.To4()))
	}

	row := db.doPrepareTotal(len(client), args)

	var sent, recv uint64
	err := row.Scan(&sent, &recv)
	if err != nil {
		return 0, 0, err
	}
	return sent, recv, row.Err()
}

func (db *DB) batcher(b <-chan func(*sql.Tx) error) {
	tx, err := db.db.BeginTx(context.Background(), nil)
	if err != nil {
		log.Fatalln("fail to start transation", err)
	}
	defer func() {
		if err := tx.Commit(); err != nil {
			log.Println("fail to commit audit log", err)
		}
	}()

	const Tick = 30 * time.Second
	timer := time.NewTimer(Tick)
	for {
	batch:
		for {
			select {
			case <-timer.C:
				break batch
			case r, ok := <-b:
				if !ok {
					return
				}
				err = r(tx)
				if errors.Is(err, errFlush) {
					break batch
				}
			}
		}

		err = tx.Commit()
		if err != nil {
			log.Println("fail to commit audit log", err)
		}
		tx, err = db.db.BeginTx(context.Background(), nil)
		if err != nil {
			log.Fatalln("fail to start transation", err)
		}
		if !timer.Stop() {
			<-timer.C
		}
		timer.Reset(Tick)
	}
}

func (db *DB) Flush() {
	db.batch <- func(tx *sql.Tx) error {
		return errFlush
	}
	done := make(chan struct{})
	db.batch <- func(tx *sql.Tx) error {
		close(done)
		return nil
	}
	<-done
}
