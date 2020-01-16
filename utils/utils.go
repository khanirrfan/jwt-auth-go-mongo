package utils

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/davecgh/go-spew/spew"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-mongo/models"
	"golang.org/x/crypto/bcrypt"
)

func RespondWithError(w http.ResponseWriter, status int, error models.Error) {
	// var error models.Error
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(error)
}
func ResponseJSON(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
}
func ComparePasswords(hashedPassword, password []byte) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), password)

	if err != nil {
		log.Println(err)
		return false
	}
	return true
}
func GenerateToken(user models.User) (string, error) {
	var err error
	secret := os.Getenv("SECRET")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss":   "course",
	})
	spew.Dump(token)

	tokenstring, err := token.SignedString([]byte(secret))
	if err != nil {
		log.Fatal(err)
	}
	return tokenstring, nil
}
