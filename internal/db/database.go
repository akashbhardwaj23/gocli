package db

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/akashbhardwaj23/cli-auth/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func Open(path string) (*gorm.DB, error) {
	fmt.Println(path)
	dir := filepath.Dir(path)
	//Because mkdirAll doesn't consider already existing directory as a error
	if err := os.MkdirAll(dir, 0700); err != nil {
		print(err.Error(), "hi")
		return nil, err
	}

	database, err := gorm.Open(
		sqlite.Open(path),
		&gorm.Config{},
	)

	if err != nil {
		return nil, err
	}

	return database, nil
}

func Migrate(database *gorm.DB) error {
	return database.AutoMigrate(
		&models.User{},
	)
}
