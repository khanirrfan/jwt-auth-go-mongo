package models

type Error struct {
	Message string `json:"message, omitempty" bson:"message,omitempty"`
}
