package database

import (
	"github.com/hirakhax/gobee/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var Db *gorm.DB

func ConnectDB() error {
	db, err := gorm.Open(sqlite.Open("db.sqlite"), &gorm.Config{})
	if err != nil {
		return err
	}
	Db = db
	Db.AutoMigrate(&models.User{})
	return nil
}
