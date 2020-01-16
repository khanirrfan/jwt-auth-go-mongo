package controllers

import (
	"fmt"
	"net/http"
)

func protectedEndPoint(w http.ResponseWriter, r *http.Request) {
	fmt.Println("portected called")
}
