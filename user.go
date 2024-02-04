// user.go
package main

import (
	_ "database/sql"
	"net/http"

	_ "github.com/lib/pq"
	_ "golang.org/x/crypto/bcrypt"
)

type UserProfile struct {
	Username string
	Role     string
}

// GetUserProfile возвращает профиль пользователя по его имени
func GetUserProfile(username string) (UserProfile, error) {
	var userProfile UserProfile
	err := db.QueryRow("SELECT username, role FROM users WHERE username = $1", username).Scan(&userProfile.Username, &userProfile.Role)
	if err != nil {
		return UserProfile{}, err
	}
	return userProfile, nil
}

// UpdateUserProfile обновляет профиль пользователя в базе данных
func UpdateUserProfile(username, newRole string) error {
	_, err := db.Exec("UPDATE users SET role = $1 WHERE username = $2", newRole, username)
	if err != nil {
		return err
	}
	return nil
}

// getUsernameFromSession возвращает имя пользователя из сессии
// getUserFromSession возвращает профиль пользователя из сессии по имени
func getUserFromSession(r *http.Request) UserProfile {
	// Здесь вы можете добавить логику получения профиля пользователя из сессии.
	// В данном примере предполагается, что имя пользователя хранится в куках.

	cookie, err := r.Cookie("username")
	if err != nil {
		return UserProfile{} // Возвращаем пустой профиль, если имя пользователя не найдено
	}

	// Создаем и возвращаем профиль пользователя с именем из сессии
	return UserProfile{
		Username: cookie.Value,
		// Добавьте другие поля профиля пользователя, если они есть
	}
}
