package main

import (
	"net/http"
	"context"
	"strings"
)

// AuthMiddleware проверяет JWT токен и устанавливает контекст пользователя
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO: Реализуйте проверку JWT токена
		//
		// Что нужно сделать:
		// 1. Импортируйте "context" и "strings"
		// 2. Получите заголовок Authorization из запроса
		// 3. Проверьте, что заголовок не пустой
		// 4. Проверьте формат "Bearer <token>" и извлеките токен
		// 5. Валидируйте токен с помощью ValidateToken() из auth.go
		// 6. Добавьте данные пользователя в контекст запроса
		// 7. Передайте управление следующему обработчику
		//
		// Если токен невалиден - верните 401 Unauthorized
		// Если токен отсутствует - верните 401 Unauthorized
		//
		// Используйте:
		// - r.Header.Get("Authorization")
		// - strings.TrimPrefix(authHeader, "Bearer ")
		// - context.WithValue(r.Context(), "userID", claims.UserID)
		// - next.ServeHTTP(w, r.WithContext(ctx))


		// Извлекаем токен из заголовка Authorization
		authHeader := r.Header.Get("Authorization")

		if authHeader == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := ValidateToken(token)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Добавляем информацию о пользователе в контекст
		ctx := context.WithValue(r.Context(), "userID", claims.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// GetUserIDFromContext извлекает ID пользователя из контекста
func GetUserIDFromContext(r *http.Request) (int, bool) {
	// TODO: Реализуйте извлечение userID из контекста
	//
	// Что нужно сделать:
	// 1. Используйте r.Context().Value("userID")
	// 2. Проведите type assertion к int
	// 3. Верните значение и булевый флаг успешности
	//
	// Пример: userID, ok := r.Context().Value("userID").(int)

	userID, ok := r.Context().Value("userID").(int)
	return userID, ok
}
