package db

import (
	"context"
	"database/sql"
	"log"
	"time"

	_ "github.com/lib/pq"
)

var Conn *sql.DB

func InitPostgres(dsn string) {
	var err error
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	Conn, err = sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("DB Connection error: %v", err)
	}

	if err = Conn.PingContext(ctx); err != nil {
		log.Fatalf("DB ping failed: %v", err)
	}
	log.Println("PostgreSQL connected")
}

func CloseDB() {
	if Conn != nil {
		if err := Conn.Close(); err != nil {
			log.Printf("Error closing DB: %v", err)
		} else {
			log.Println("PostgreSQL connection closed")
		}
	}
}
