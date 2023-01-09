package main

import (
	"github.com/labstack/gommon/log"
	"lars-krieger.de/pseudo-kms/database"
	"lars-krieger.de/pseudo-kms/rest"
	"os"
	"strconv"
	"time"
)

func main() {
	/*
		log.Printf("%v", Config)
		//Database configs
		Config.DatabaseHost = os.Getenv("DATABASE_HOST")
		Config.DatabasePort = os.Getenv("DATABASE_PORT")
		Config.DatabasePassword = os.Getenv("POSTGRES_PASSWORD")
		Config.DatabaseUser = os.Getenv("POSTGRES_USER")
		Config.DatabaseDBName = os.Getenv("POSTGRES_DB")
	*/
	ginPort, err := strconv.Atoi(os.Getenv("GIN_PORT"))
	if err != nil {
		log.Errorf("Gin Port could not be parsed: %s", err.Error())
		return
	}

	for i := 0; i != 3; i++ {
		log.Info("Waiting for Database to be online")
		time.Sleep(1 * time.Second)
	}

	database.Init(
		os.Getenv("POSTGRES_USER"),
		os.Getenv("POSTGRES_PASSWORD"),
		os.Getenv("DATABASE_HOST"),
		os.Getenv("POSTGRES_DB"),
		os.Getenv("DATABASE_PORT"),
	)

	database.CreateUser(os.Getenv("ADMIN_USER"), os.Getenv("ADMIN_PASSWORD"), true)

	rest.Router("localhost", ginPort)

	//rsa.GenerateDefaultPrivateKey()
}
