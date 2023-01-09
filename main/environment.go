package main

var Config EnvironmentConfig

type EnvironmentConfig struct {
	//Database
	DatabaseHost     string
	DatabasePort     string
	DatabaseUser     string
	DatabasePassword string
	DatabaseDBName   string
	//Admin User
	AdminUser     string
	AdminPassword string
	//Rest
	GinPort int
}
