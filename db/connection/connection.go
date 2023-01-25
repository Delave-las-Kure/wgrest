package connection

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func Open() (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open("file:/var/lib/wgrest/wg.db?mode=rwc&cache=shared&_fk=1"), &gorm.Config{})
	if res := db.Exec("PRAGMA foreign_keys = ON", nil); res.Error != nil {
		return db, err
	}
	return db, err
}
