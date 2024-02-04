// tmpl/helper.go
package tmpl

import "net/http"

// RedirectWithMethod выполняет перенаправление на указанный адрес с сохранением метода запроса.
func RedirectWithMethod(w http.ResponseWriter, r *http.Request, address string) {
	if address == "" {
		address = "/"
	}
	w.Header().Set("Location", address)
	w.Header().Set("Cache-Control", "private, no-store, max-age=0, must-revalidate")
	w.WriteHeader(http.StatusSeeOther) // Используем код 303 See Other
}
