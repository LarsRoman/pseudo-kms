package models

import (
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

type AccessUser struct {
	gorm.Model
	Name      string `gorm:"unique;not null;type:varchar(256);default:null"`
	Token     string `gorm:"not null;type:varchar(2048);default:null"`
	PowerUser bool   `gorm:"type:boolean;default:false"`
}

type Keystore struct {
	gorm.Model
	AccessUserId string `gorm:"unique;not null;type:varchar(128);default:null"`
}

type Keys struct {
	gorm.Model
	KeyName    string `gorm:"not null;type:varchar(128);default:null"`
	KeyVersion int    `gorm:"not null;type:integer;default:null"`
	KeyAlg     string `gorm:"not null;type:varchar(128);default:null"`
	KeySize    int    `gorm:"type:integer;default:null"`
	KeyCurve   string `gorm:"type:varchar(128);default:null"`
	KeyUse     string `gorm:"type:varchar(128);default:null"`
	PrivateKey string `gorm:"unique;not null;type:varchar(655360);default:null"`
	PublicKey  string `gorm:"unique;not null;type:varchar(65536);default:null"`
	Keystore   string `gorm:"not null;type:varchar(128);default:null"`
}
