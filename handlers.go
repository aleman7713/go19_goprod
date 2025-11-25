package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
)

// RegisterHandler обрабатывает регистрацию нового пользователя
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// TODO: Реализуйте регистрацию пользователя
	//
	// Пошаговый план:
	// 1. Распарсите JSON из тела запроса в структуру RegisterRequest
	// 2. Проведите валидацию данных (email, username, password)
	// 3. Проверьте, что пользователь с таким email не существует
	// 4. Захешируйте пароль с помощью функции HashPassword()
	// 5. Создайте пользователя в БД с помощью CreateUser()
	// 6. Сгенерируйте JWT токен с помощью GenerateToken()
	// 7. Верните ответ с токеном и данными пользователя
	//
	// Подсказки:
	// - Используйте json.NewDecoder(r.Body).Decode() для парсинга JSON
	// - Проверьте что все обязательные поля заполнены
	// - При ошибках возвращайте соответствующие HTTP статусы
	// - 400 для невалидных данных, 409 для дубликатов, 500 для внутренних ошибок
	// - Не забудьте установить Content-Type: application/json для ответа

	var reg RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
		http.Error(w, "Неверный формат данных: " + err.Error(), http.StatusBadRequest)
		return
	}

	// Валидация данных
	if err := validateRegisterRequest(&reg); err != nil {
		http.Error(w, "Валидация данных не пройдена: " + err.Error(), http.StatusBadRequest)
		return
	}

	// Проверьте, что пользователь с таким email не существует
	if _, err := GetUserByEmail(reg.Email); err == nil {
		http.Error(w, "Пользователь с таким email уже существует: " + reg.Email, http.StatusConflict)
		return
	}

	// Захешируйте пароль с помощью функции HashPassword()
	var err error
	var pwdHash string
	pwdHash, err = HashPassword(reg.Password)
	if err != nil {
		http.Error(w, "Неудалось захешировать пароль", http.StatusInternalServerError)
		return
	}

	// Создайте пользователя в БД с помощью CreateUser()
	var user *User
	if user, err = CreateUser(reg.Email, reg.Username, pwdHash); err != nil {
		http.Error(w, "Неудалось создать пользователя", http.StatusInternalServerError)
		return
	}

	// Сгенерируйте JWT токен с помощью GenerateToken()
	var token string
	if token, err = GenerateToken(*user); err != nil {
		http.Error(w, "Неудалось создать токен", http.StatusInternalServerError)
		return
	}

	// Верните ответ с токеном и данными пользователя
	result := AuthResponse{
		Token: token,
		User: *user,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

// LoginHandler обрабатывает вход пользователя
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// TODO: Реализуйте авторизацию пользователя
	//
	// Пошаговый план:
	// 1. Распарсите JSON из тела запроса в структуру LoginRequest
	// 2. Проведите базовую валидацию (email и password не пустые)
	// 3. Найдите пользователя по email с помощью GetUserByEmail()
	// 4. Проверьте пароль с помощью CheckPassword()
	// 5. Сгенерируйте JWT токен с помощью GenerateToken()
	// 6. Верните ответ с токеном и данными пользователя
	//
	// Важные моменты безопасности:
	// - При неверном email или пароле возвращайте одинаковое сообщение
	//   "Invalid email or password" чтобы не раскрывать существование email
	// - Используйте HTTP статус 401 для неверных учетных данных
	// - Не возвращайте password_hash в ответе

	var login LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&login); err != nil {
		http.Error(w, "Неверный формат данных", http.StatusBadRequest)
		return
	}

	if err := validateLoginRequest(&login); err != nil {
		http.Error(w, "Invalid email or password", http.StatusBadRequest)
		return
	}

	// Найдите пользователя по email с помощью GetUserByEmail()
	var user *User
	var err error
	if user, err = GetUserByEmail(login.Email); err != nil {
		http.Error(w, "Invalid email or password", http.StatusBadRequest)
		return
	}

	// Проверьте пароль с помощью CheckPassword()
	if !CheckPassword(login.Password, user.PasswordHash) {
		http.Error(w, "Invalid email or password", http.StatusBadRequest)
		return
	}

	// Сгенерируйте JWT токен с помощью GenerateToken()
	var token string
	if token, err = GenerateToken(*user); err != nil {
		http.Error(w, "Неудалось создать токен", http.StatusInternalServerError)
		return
	}

	// Верните ответ с токеном и данными пользователя
	result := AuthResponse{
		Token: token,
		User: *user,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

// ProfileHandler возвращает профиль текущего пользователя
func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// TODO: Реализуйте получение профиля пользователя
	//
	// Пошаговый план:
	// 1. Получите ID пользователя из контекста с помощью GetUserIDFromContext()
	// 2. Загрузите данные пользователя из БД с помощью GetUserByID()
	// 3. Верните данные пользователя в JSON формате
	//
	// Примечания:
	// - Этот обработчик вызывается только после AuthMiddleware
	// - Контекст уже должен содержать userID
	// - Если пользователь не найден - верните 404
	// - Не включайте password_hash в ответ

	user_id, is_ok := GetUserIDFromContext(r)
	if !is_ok {
		http.Error(w, "Неверный формат данных", http.StatusBadRequest)
		return
	}

	user, err := GetUserByID(user_id)
	if err != nil {
		http.Error(w, "Пользователя с таким ID не существует: " + string(user_id), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(*user)
}

// HealthHandler проверяет состояние сервиса
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	// Проверяем подключение к БД
	if db != nil {
		if err := db.Ping(); err != nil {
			http.Error(w, "Database connection failed", http.StatusServiceUnavailable)
			return
		}
	}

	// Возвращаем статус OK
	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{
		"status":  "ok",
		"message": "Service is running",
	}
	json.NewEncoder(w).Encode(response)
}

// sendJSONResponse отправляет JSON ответ (вспомогательная функция)
func sendJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// sendErrorResponse отправляет JSON ответ с ошибкой (вспомогательная функция)
func sendErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := map[string]string{"error": message}
	json.NewEncoder(w).Encode(response)
}

// parseJSONRequest парсит JSON из тела запроса (вспомогательная функция)
func parseJSONRequest(r *http.Request, v interface{}) error {
	if r.Body == nil {
		return fmt.Errorf("request body is empty")
	}
	defer r.Body.Close()

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields() // Строгая проверка полей

	return decoder.Decode(v)
}

// validateRegisterRequest валидирует данные регистрации
func validateRegisterRequest(req *RegisterRequest) error {
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if req.Username == "" {
		return fmt.Errorf("username is required")
	}
	if req.Password == "" {
		return fmt.Errorf("password is required")
	}

	// TODO: Добавьте дополнительные проверки
	// - Используйте ValidateEmail() и ValidatePassword() из auth.go
	// - Проверьте длину username (например, минимум 3 символа)
	// - Проверьте что username содержит только допустимые символы

	if err := ValidateEmail(req.Email); err != nil {
		return fmt.Errorf("email is incorrect: " + err.Error())
	}
	if err := ValidatePassword(req.Password); err != nil {
		return fmt.Errorf("password is incorrect: " + err.Error())
	}
	if len(req.Username) < 3 {
		return fmt.Errorf("username must be at least 3 characters long")
	}
	// Проверяем, не содержатся ли запрещенные символы
	match, _ := regexp.MatchString(`^[a-z0-9._-]+$`, req.Username)
	if !match {
		return fmt.Errorf("username содержит запрещённые символы")
	}

	return nil
}

// validateLoginRequest валидирует данные входа
func validateLoginRequest(req *LoginRequest) error {
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if req.Password == "" {
		return fmt.Errorf("password is required")
	}
	return nil
}
