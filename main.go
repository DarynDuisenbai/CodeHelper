// main.go
package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"net/http"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

const (
	host     = "localhost"
	port     = 5432
	user     = "postgres"
	password = "mother1978"
	dbname   = "forum"
)

var db *sql.DB

type PageVariables struct {
	Title string
}

type User struct {
	Username string
	Password string
	Role     string
}

func main() {
	var err error
	db, err = sql.Open("postgres", fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, dbname))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	http.HandleFunc("/", HomePage)
	http.HandleFunc("/register", RegisterPage)
	http.HandleFunc("/login", LoginPage)
	http.HandleFunc("/admin", AdminPage)

	fmt.Println("Server is running on :8080...")
	http.ListenAndServe(":8080", nil)
}

func HomePage(w http.ResponseWriter, r *http.Request) {
	pageVariables := PageVariables{
		Title: "Ваш форум",
	}

	tmpl, err := template.ParseFiles("index.html")
	if err != nil {
		fmt.Println("Error parsing template:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl.Execute(w, pageVariables)
}

func RegisterPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		role := "user" // You can set a default role for registered users
		_, err = db.Exec("INSERT INTO users (username, password, role) VALUES ($1, $2, $3)", username, hashedPassword, role)
		if err != nil {
			http.Error(w, "Error creating user", http.StatusInternalServerError)
			return
		}

		// Redirect to login page after successful registration
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	tmpl, err := template.ParseFiles("register.html")
	if err != nil {
		fmt.Println("Error parsing template:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl.Execute(w, nil)
}

func LoginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		var hashedPassword string
		var role string
		err := db.QueryRow("SELECT password, role FROM users WHERE username = $1", username).Scan(&hashedPassword, &role)
		if err != nil {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		if err != nil {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		if username == "admin" && password == "admin" {
			// Redirect to the admin panel for the hardcoded admin credentials
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}

		if role == "admin" {
			// Redirect to the admin panel for users with admin role
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
		} else {
			// Redirect to the home page for regular users
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
		return
	}

	tmpl, err := template.ParseFiles("login.html")
	if err != nil {
		fmt.Println("Error parsing template:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl.Execute(w, nil)
}

func AdminPage(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("admin.html")
	if err != nil {
		fmt.Println("Error parsing template:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl.Execute(w, nil)
}
