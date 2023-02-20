package migration

import (
	"context"
	"log"

	"github.com/Delave-las-Kure/wgrest/db/connection"
	"github.com/Delave-las-Kure/wgrest/db/model"
)

func Run(ctx context.Context) {
	client, err := connection.Open()

	if err != nil {
		log.Fatalf("failed opening connection to sqlite: %v", err)
		panic("failed to connect database")
	}

	client.WithContext(ctx).AutoMigrate( /*&model.User{},*/ &model.Peer{}, &model.AllowedIP{})
}
