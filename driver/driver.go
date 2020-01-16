package driver

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	// "github.com/mongodb/mongo-go-driver/bson"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var client *mongo.Database

func ConnectDB() *mongo.Database {

	clientOptions, err := mongo.NewClient(options.Client().ApplyURI(os.Getenv("MONGO_URL")))
	// client, _ = mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	err = clientOptions.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer cancel()

	client = clientOptions.Database("userDetails")
	fmt.Println("client:", client)
	return client
}
