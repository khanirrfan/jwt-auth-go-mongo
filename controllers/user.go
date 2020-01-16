package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-mongo/models"
	"github.com/go-mongo/utils"
	// "github.com/mongodb/mongo-go-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	// "github.com/mongodb/mongo-go-driver/bson"
	"golang.org/x/crypto/bcrypt"
)

type Controller struct{

}
func (c controller) Signup(client *mongo.Database) http.HandlerFunc{

return func(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("content-type", "application/json")
	var user models.User
	var error models.Error
	json.NewDecoder(r.Body).Decode(&user)
	if user.Email == "" {
		error.Message = "Email is Missing"
		utils.RespondWithError(w, http.StatusBadRequest, error)
		return
	}
	if user.Password == "" {
		error.Message = "Password is Missing"
		utils.RespondWithError(w, http.StatusBadRequest, error)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
	if err != nil {
		log.Fatal(err)
	}

	user.Password = string(hash)
	// fmt.Println("password after hashing", user.Password)

	collection := client.Collection("user")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	result, err := collection.InsertOne(ctx, user)
	fmt.Println("result:", result)
	json.NewEncoder(w).Encode(result)

	if err != nil {
		error.Message = "Server Error here"
		utils.RespondWithError(w, http.StatusInternalServerError, error)
		return
	}

	user.Password = ""
	w.Header().Set("Content-Type", "application/json")
	// json.NewEncoder(w).Encode(user)
	fmt.Println("user:", user)
	utils.ResponseJSON(w, user)
}

func login(w http.ResponseWriter, r *http.Request) {
	var user models.User
	var jwt models.JWT
	var error models.Error
	json.NewDecoder(r.Body).Decode(&user)
	// spew.Dump(&user)

	if user.Email == "" {
		error.Message = "Email is missing"
		utils.RespondWithError(w, http.StatusBadRequest, error)
		return
	}

	if user.Password == "" {
		error.Message = "Password is missing"
		utils.RespondWithError(w, http.StatusBadRequest, error)
		return
	}
	password := user.Password

	collection := client.Collection("user")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err := collection.FindOne(ctx, user.Email)
	fmt.Println("err:", err)
	if err != nil {
		error.Message = "User Does Not Exist"
		utils.RespondWithError(w, http.StatusBadRequest, error)
		return
	}
	// spew.Dump(user)
	hashedPassword := user.Password
	// err1 := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		log.Fatal(err)
		// error.Message = "Invald Password"
		// utils.RespondWithError(w, http.StatusUnauthorized, error)
		// return
	}

	token, err := utils.GenerateToken(user)

	if err != nil {
		log.Fatal(err)
	}
	w.WriteHeader(http.StatusOK)
	jwt.Token = token

	utils.ResponseJSON(w, jwt)

}

func getUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("content-type", "application/json")
	var user []models.User
	collection := client.Collection("user")
	ctx, _ := context.WithTimeout(context.Background(), 50*time.Second)
	cursor, err := collection.Find(ctx, bson.M{})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"messages":" ` + err.Error() + `"}`))
		return
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var users models.User
		cursor.Decode(&users)
		user = append(user, users)
	}
	if err := cursor.Err(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"messages":" ` + err.Error() + `"}`))
		return
	}
	json.NewEncoder(w).Encode(user)
}

func TokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc {
	// fmt.Println("postMyDetails called")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var errorObject models.Error
		authHeader := r.Header.Get("AUthorized")
		bearerToken := strings.Split(authHeader, " ")

		if len(bearerToken) == 2 {
			authToken := bearerToken[1]

			token, error := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}
				// spew.Dump(token)

				return []byte(os.Getenv("SECRET")), nil

			})

			if error != nil {
				errorObject.Message = error.Error()
				utils.RespondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}
			if token.Valid {
				next.ServeHTTP(w, r)
			} else {
				errorObject.Message = error.Error()
				utils.RespondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}
		} else {
			errorObject.Message = "Invalid Token"
			utils.RespondWithError(w, http.StatusUnauthorized, errorObject)
			return
		}
	})

}
