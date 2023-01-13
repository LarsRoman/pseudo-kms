package database

import (
	"fmt"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/labstack/gommon/log"
	"lars-krieger.de/pseudo-kms/database/models"
	"strings"
)

var DB *gorm.DB

func Init(user, pass, host, dbName, port, debugging string) {
	if err := initDatabase(user, pass, host, dbName, port); err != nil {
		_ = initDatabase(user, pass, "host.docker.internal", dbName, port)
	}

	if strings.ToLower(debugging) == "true" {
		DB = DB.Debug()
	}

	DB.AutoMigrate(
		&models.AccessUser{},
		&models.Keystore{},
		&models.Keys{},
	)
}

func initDatabase(user, pass, host, dbName, port string) error {
	dbUrl := fmt.Sprintf("host=%s port=%s user=%s dbname=%s sslmode=disable password=%s",
		host,
		port,
		user,
		dbName,
		pass,
	)
	log.Errorf("Postgres copnnection string: %s", dbUrl)
	if db, err := gorm.Open("postgres", dbUrl); err != nil {
		log.Errorf("Connection to postgres was not possible: %s", err.Error())
		return err
	} else {
		DB = db
	}
	return nil
}
