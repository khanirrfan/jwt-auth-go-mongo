package models

type JWT struct {
	Token string `json:"token, omitempty" bson:"token, omitempty"`
}
