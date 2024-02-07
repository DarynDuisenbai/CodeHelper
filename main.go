package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	_ "log"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/juju/ratelimit"
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
	Title     string
	User      UserProfile
	Questions []Question
}

type User struct {
	Username string
	Password string
	Role     string
}

type Question struct {
	ID             int
	Text           string
	Author         string
	CreatedAt      time.Time
	AddingQuestion bool
	Answers        []Answer
	Category       string // Добавьте это поле
}

type Answer struct {
	ID        int
	Text      string
	Author    string
	CreatedAt time.Time
}

type QuestionWithAnswers struct {
	ID        int
	Text      string
	Author    string
	Category  string
	CreatedAt time.Time
	Answer    Answer
}

var goQuestions []Question

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
	//http.HandleFunc("/profile", ProfilePage)
	http.HandleFunc("/go", GoPage)
	http.HandleFunc("/java", JavaPage)
	http.HandleFunc("/javascript", JavaScriptPage)
	http.HandleFunc("/python", PythonPage)

	log.Println("Server is running on :8080...")
	http.ListenAndServe(":8080", nil)
}

// ratelimiting
var limiter = ratelimit.NewBucket(time.Second, 10)
var mutex sync.Mutex

func RateLimitedHandler(w http.ResponseWriter, r *http.Request) {
	mutex.Lock()
	defer mutex.Unlock()

	if limiter.TakeAvailable(1) < 1 {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

}
func HomePage(w http.ResponseWriter, r *http.Request) {
	pageVariables := PageVariables{
		Title: "Ваш форум",
	}

	tmpl, err := template.ParseFiles("index.html")
	if err != nil {
		log.Println("Error parsing template:", err)
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

/*func ProfilePage(w http.ResponseWriter, r *http.Request) {
	// Получаем имя пользователя из сессии или из параметра запроса
	username := getUsernameFromSession(r)

	// Если пользователь не авторизован, перенаправляем на страницу входа
	if username == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Получаем профиль пользователя
	userProfile, err := GetUserProfile(username)
	if err != nil {
		fmt.Println("Error retrieving user profile:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	pageVariables := PageVariables{
		Title: "Профиль пользователя",
		User:  userProfile,
	}

	tmpl, err := template.ParseFiles("profile.html")
	if err != nil {
		fmt.Println("Error parsing template:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl.Execute(w, pageVariables)
}

*/

func GoPage(w http.ResponseWriter, r *http.Request) {
	// Проверяем, был ли отправлен запрос на удаление вопроса
	deleteQuestionID, err := strconv.Atoi(r.FormValue("deleteQuestionID"))
	if err == nil && deleteQuestionID > 0 {
		err := deleteQuestion(deleteQuestionID)
		if err != nil {
			fmt.Println("Error deleting question:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}

	if r.Method == http.MethodPost {
		// Обработка добавления вопроса
		text := r.FormValue("question")
		author := getUserFromSession(r).Username
		category := r.FormValue("category")
		err := addQuestion(text, author, category)
		if err != nil {
			fmt.Println("Error adding question:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Обработка отправки ответа
		answerText := r.FormValue("answer")
		questionID, err := strconv.Atoi(r.FormValue("questionID"))
		if err == nil && questionID > 0 {
			err := addAnswer(questionID, answerText, author)
			if err != nil {
				fmt.Println("Error adding answer:", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
		}

		// Обработка удаления ответа
		deleteAnswerID, err := strconv.Atoi(r.FormValue("deleteAnswerID"))
		if err == nil && deleteAnswerID > 0 {
			err := deleteAnswer(deleteAnswerID)
			if err != nil {
				fmt.Println("Error deleting answer:", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
		}

		// Обработка редактирования ответа
		editAnswerID, err := strconv.Atoi(r.FormValue("editAnswerID"))
		if err == nil && editAnswerID > 0 {
			// Здесь вы можете добавить логику для редактирования ответа
			// Например, вызов функции editAnswer(editAnswerID, newText)
			// Замените "newText" на актуальный текст ответа
		}
	}

	questionsWithAnswers, err := getQuestionsWithAnswers()
	if err != nil {
		fmt.Println("Error getting questions with answers:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Создаем новый срез вопросов, соответствующий ожидаемому типу
	var questions []Question
	for _, qa := range questionsWithAnswers {
		questions = append(questions, Question{
			ID:        qa.ID,
			Text:      qa.Text,
			Author:    qa.Author,
			Category:  qa.Category,
			CreatedAt: qa.CreatedAt,
			Answers:   []Answer{qa.Answer},
		})
	}

	tmpl, err := template.ParseFiles("go.html")
	if err != nil {
		log.Println("Error parsing template:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	pageVariables := PageVariables{
		Title:     "Golang Questions",
		User:      getUserFromSession(r),
		Questions: questions,
	}

	tmpl.Execute(w, pageVariables)
}

func JavaPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Обработка добавления вопроса
		text := r.FormValue("question")
		author := getUserFromSession(r).Username
		category := r.FormValue("category") // Assuming you have a category input in your form
		err := addQuestion(text, author, category)
		if err != nil {
			fmt.Println("Error adding question:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}

	// Получаем список вопросов (может потребоваться сортировка и фильтрация)
	// ...

	// Здесь вы можете использовать шаблонизатор для отображения страницы
	tmpl, err := template.ParseFiles("java.html")
	if err != nil {
		log.Println("Error parsing template:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Используйте тип UserProfile вместо User
	userProfile := getUserFromSession(r)
	pageVariables := PageVariables{
		Title:     "Java Questions",
		User:      userProfile,
		Questions: goQuestions, // Передаем список вопросов в шаблон
		// Добавьте сюда другие необходимые переменные
	}

	tmpl.Execute(w, pageVariables)
}

func JavaScriptPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Обработка добавления вопроса
		text := r.FormValue("question")
		author := getUserFromSession(r).Username
		category := r.FormValue("category") // Assuming you have a category input in your form
		err := addQuestion(text, author, category)
		if err != nil {
			log.Println("Error adding question:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}

	// Получаем список вопросов (может потребоваться сортировка и фильтрация)
	// ...

	// Здесь вы можете использовать шаблонизатор для отображения страницы
	tmpl, err := template.ParseFiles("js.html")
	if err != nil {
		log.Println("Error parsing template:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Используйте тип UserProfile вместо User
	userProfile := getUserFromSession(r)
	pageVariables := PageVariables{
		Title:     "JavaScript Questions",
		User:      userProfile,
		Questions: goQuestions,
	}

	tmpl.Execute(w, pageVariables)
}

func PythonPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {

		text := r.FormValue("question")
		author := getUserFromSession(r).Username
		category := r.FormValue("category") // Assuming you have a category input in your form
		err := addQuestion(text, author, category)
		if err != nil {
			log.Println("Error adding question:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}

	// Здесь вы можете использовать шаблонизатор для отображения страницы
	tmpl, err := template.ParseFiles("python.html")
	if err != nil {
		log.Println("Error executing query:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Используйте тип UserProfile вместо User
	userProfile := getUserFromSession(r)
	pageVariables := PageVariables{
		Title:     "Python Questions",
		User:      userProfile,
		Questions: goQuestions,
	}

	tmpl.Execute(w, pageVariables)
}

// Пример добавления логирования в функцию addQuestion
func addQuestion(text, author, category string) error {
	query := "INSERT INTO questions (text, author, category) VALUES ($1, $2, $3)"
	_, err := db.Exec(query, text, author, category)
	if err != nil {
		log.Println("Error executing query:", err)
	}
	return err
}

func addAnswer(questionID int, text, author string) error {
	_, err := db.Exec("INSERT INTO answers (question_id, text, author) VALUES ($1, $2, $3)", questionID, text, author)
	return err
}

func getQuestions() []Question {
	// Здесь вы можете добавить логику для получения списка вопросов из базы данных
	// ...

	// Пример запроса к базе данных для получения всех вопросов
	rows, err := db.Query("SELECT id, text, author, created_at FROM questions ORDER BY created_at DESC")
	if err != nil {
		log.Println("Error executing query:", err)
		return nil
	}
	defer rows.Close()

	var questions []Question
	for rows.Next() {
		var question Question
		err := rows.Scan(&question.ID, &question.Text, &question.Author, &question.CreatedAt)
		if err != nil {
			log.Println("Error executing query:", err)
			return nil
		}
		questions = append(questions, question)
	}

	return questions
}

func addQuestionAndGetID(text, author string) (int, error) {
	var questionID int
	err := db.QueryRow("INSERT INTO questions (text, author) VALUES ($1, $2) RETURNING id", text, author).Scan(&questionID)
	return questionID, err
}

func editAnswer(answerID int, newText string) error {
	_, err := db.Exec("UPDATE answers SET text = $1 WHERE id = $2", newText, answerID)
	return err
}

// deleteQuestion удаляет вопрос из базы данных
func deleteQuestion(questionID int) error {
	_, err := db.Exec("DELETE FROM questions WHERE id = $1", questionID)
	return err
}

// deleteAnswer удаляет ответ из базы данных
func deleteAnswer(answerID int) error {
	_, err := db.Exec("DELETE FROM answers WHERE id = $1", answerID)
	return err
}

// getQuestionsWithAnswers возвращает вопросы с соответствующими ответами
func getQuestionsWithAnswers() ([]QuestionWithAnswers, error) {
	rows, err := db.Query("SELECT q.id, q.text AS question_text, q.author AS question_author, q.category, q.created_at, a.id AS answer_id, a.text AS answer_text, a.author AS answer_author, a.created_at AS answer_created_at FROM questions q LEFT JOIN answers a ON q.id = a.question_id ORDER BY q.created_at DESC, a.created_at ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var questions []QuestionWithAnswers
	for rows.Next() {
		var q QuestionWithAnswers
		err := rows.Scan(&q.ID, &q.Text, &q.Author, &q.Category, &q.CreatedAt, &q.Answer.ID, &q.Answer.Text, &q.Answer.Author, &q.Answer.CreatedAt)
		if err != nil {
			return nil, err
		}
		questions = append(questions, q)
	}
	return questions, nil
}

// Sorting
type ByID []Question

func (a ByID) Len() int           { return len(a) }
func (a ByID) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByID) Less(i, j int) bool { return a[i].ID < a[j].ID }

func SortQuestionsByID(questions []Question) {
	sort.Sort(ByID(questions))
}
