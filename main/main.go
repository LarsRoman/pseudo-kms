package main

import (
	"github.com/labstack/gommon/log"
	"lars-krieger.de/pseudo-kms/crypt/helper"
	"lars-krieger.de/pseudo-kms/crypt/rsa"
	"lars-krieger.de/pseudo-kms/database"
	"lars-krieger.de/pseudo-kms/rest"
	"os"
	"strconv"
)

func main() {
	ginPort, err := strconv.Atoi(os.Getenv("GIN_PORT"))
	if err != nil {
		log.Errorf("Gin Port could not be parsed: %s", err.Error())
		return
	}

	rsa.RSA_MASTER_KEY = &rsa.RSA{
		AsymmetricOpt: helper.AsymmetricOpt{
			Name:        "MASTER KEY",
			WriteToFile: true,
			Hash:        helper.Hashes(os.Getenv("RSA_MASTER_KEY_ALG")),
			KeyTypes:    os.Getenv("RSA_MASTER_KEY_HASH"),
		},
	}
	rsa.RSA_MASTER_KEY.ReadOrCreateMasterKey()

	database.Init(
		os.Getenv("POSTGRES_USER"),
		os.Getenv("POSTGRES_PASSWORD"),
		os.Getenv("DATABASE_HOST"),
		os.Getenv("POSTGRES_DB"),
		os.Getenv("DATABASE_PORT"),
	)

	database.CreateUser(os.Getenv("ADMIN_USER"), os.Getenv("ADMIN_PASSWORD"), true)

	rest.Router(os.Getenv("GIN_HOST"), ginPort)
}
