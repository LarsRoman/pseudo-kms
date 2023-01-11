package rsa

import (
	"github.com/labstack/gommon/log"
	"os"
	fp "path/filepath"
	"strings"
)

var RSA_MASTER_KEY *RSA

func (r *RSA) ReadOrCreateMasterKey() {
	var files []string
	var filepath string = "/data/pseudo-kms"

	err := fp.Walk(filepath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Errorf("Reading key files failed: %s", err.Error())
			return nil
		}
		if !info.IsDir() && fp.Ext(path) == ".pem" {
			files = append(files, path)
		}
		return nil
	})

	if err != nil {
		log.Errorf("Reading key files failed: %s", err.Error())
		return
	}

	if len(files) > 0 {
		//data/pseudo-kms/public.pem
		//data/pseudo-kms/private-1234567890.pem
		for _, file := range files {
			if strings.Contains(file, "public") {
				if bytePuffer, err := os.ReadFile(file); err != nil {
					log.Errorf("Reading Public key file failed: %s", err.Error())
				} else {
					r.PublicKey = *MemToPublicKey(bytePuffer)
				}
			}
			if strings.Contains(file, "private") {
				if bytePuffer, err := os.ReadFile(file); err != nil {
					log.Errorf("Reading Public key file failed: %s", err.Error())
				} else {
					r.PrivateKey = *MemToPrivateKey(bytePuffer)
				}
			}
		}
	} else {
		_, _ = r.Create()
	}
}
