package main

import (
	"log"
	"os"
	"strconv"

	"github.com/akashbhardwaj23/cli-auth/internal/auth"
	"github.com/akashbhardwaj23/cli-auth/internal/cli"
	"github.com/akashbhardwaj23/cli-auth/internal/db"
	"github.com/akashbhardwaj23/cli-auth/internal/session"
)

func main() {

	dbPath := getenv(
		"DB_PATH",
		"./data/auth.db",
	)

	database, err := db.Open(dbPath)

	if err != nil {
		log.Fatal(
			"failed to open database:",
			err,
		)
	}

	if err := db.Migrate(database); err != nil {
		log.Fatal(
			"failed to migrate database:",
			err,
		)
	}

	config := auth.Config{
		LockOutThreshold: getenvInt(
			"LOCKOUT_THRESHOLD",
			5,
		),

		LocOutMinutes: getenvInt(
			"LOCKOUT_MINUTES",
			15,
		),

		SeesionTimeOut: getenvInt(
			"SESSION_TIMEOUT_MINUTES",
			30,
		),
	}

	authService := auth.NewService(
		database,
		config,
	)

	sessionManager := session.NewManager(
		config.SeesionTimeOut,
	)

	application := cli.NewApp(
		authService,
		sessionManager,
	)

	application.Run()
}

func getenv(
	key string,
	fallback string,
) string {

	value := os.Getenv(key)

	if value == "" {
		return fallback
	}

	return value
}

func getenvInt(
	key string,
	fallback int,
) int {

	value := os.Getenv(key)

	if value == "" {
		return fallback
	}

	number, err := strconv.Atoi(value)

	if err != nil || number <= 0 {
		return fallback
	}

	return number
}
