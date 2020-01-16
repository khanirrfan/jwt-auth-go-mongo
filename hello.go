package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"

	"github.com/gorilla/mux"

	// "github.com/mongodb/mongo-go-driver/bson"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type User struct {
	ID       primitive.ObjectID `json:"_id,omitempty" bson:"_id, omitempty"`
	Email    string             `json:"email, omitempty" bson:"email, omitempty"`
	Password string             `json:"password, omitempty" bson:"password, omitempty"`
}
type JWT struct {
	Token string `json:"token, omitempty" bson:"token, omitempty"`
}
type Error struct {
	Message string `json:"message, omitempty" bson:"message,omitempty"`
}

var client *mongo.Database

func main() {

	clientOptions, err := mongo.NewClient(options.Client().ApplyURI("mongodb://localhost:27017"))
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
	router := mux.NewRouter()
	// collection := client.Database("userDetails").Collection("user")
	fmt.Println("Here we go started")
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/getUser", getUser).Methods("GET")
	router.HandleFunc("/protected", TokenVerifyMiddleWare(protectedEndPoint)).Methods("GET")
	http.ListenAndServe(":8080", router)
}
func respondWithError(w http.ResponseWriter, status int, error Error) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(error)
}
func responseJSON(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
}

func getUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("content-type", "application/json")
	var user []User
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
		var users User
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
func signup(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("content-type", "application/json")
	var user User
	var error Error
	json.NewDecoder(r.Body).Decode(&user)
	if user.Email == "" {
		error.Message = "Email is Missing"
		respondWithError(w, http.StatusBadRequest, error)
		return
	}
	if user.Password == "" {
		error.Message = "Password is Missing"
		respondWithError(w, http.StatusBadRequest, error)
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
	json.NewEncoder(w).Encode(result)

	if err != nil {
		error.Message = "Server Error here"
		respondWithError(w, http.StatusInternalServerError, error)
		return
	}

	user.Password = ""
	w.Header().Set("Content-Type", "application/json")
	// json.NewEncoder(w).Encode(user)
	fmt.Println("user:", user)
	responseJSON(w, user)
}

func GenerateToken(user User) (string, error) {
	var err error
	secret := "secret"
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
func login(w http.ResponseWriter, r *http.Request) {
	var user User
	var jwt JWT
	var error Error
	json.NewDecoder(r.Body).Decode(&user)
	// spew.Dump(&user)

	if user.Email == "" {
		error.Message = "Email is missing"
		respondWithError(w, http.StatusBadRequest, error)
		return
	}

	if user.Password == "" {
		error.Message = "Password is missing"
		respondWithError(w, http.StatusBadRequest, error)
		return
	}
	password := user.Password

	collection := client.Collection("user")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err := collection.FindOne(ctx, user.Email)
	fmt.Println("err:", err)
	if err != nil {
		error.Message = "User Does Not Exist"
		respondWithError(w, http.StatusBadRequest, error)
		return
	}
	// spew.Dump(user)
	hashedPassword := user.Password
	err1 := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err1 != nil {
		error.Message = "Invald Password"
		respondWithError(w, http.StatusUnauthorized, error)
		return
	}

	token, err1 := GenerateToken(user)

	if err1 != nil {
		log.Fatal(err)
	}
	w.WriteHeader(http.StatusOK)
	jwt.Token = token

	responseJSON(w, jwt)

}
func TokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc {
	// fmt.Println("postMyDetails called")
	return http.HandleryFunc(func(w http.ResponseWriter, r *http.Request) {
		var errorObject Error
		authHeader := r.Header.Get("AUthorized")
		bearerToken := strings.Split(authHeader, " ")

		if len(bearerToken) == 2 {
			authToken := bearerToken[1]

			token, error := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}
				// spew.Dump(token)

				return []byte("secret"), nil

			})

			if error != nil {
				errorObject.Message = error.Error()
				respondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}
			if token.Valid {
				next.ServeHTTP(w, r)
			} else {
				errorObject.Message = error.Error()
				respondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}
		} else {
			errorObject.Message = "Invalid Token"
			respondWithError(w, http.StatusUnauthorized, errorObject)
			return
		}
	})
}
func protectedEndPoint(w http.ResponseWriter, r *http.Request) {
	fmt.Println("portected called")
}
