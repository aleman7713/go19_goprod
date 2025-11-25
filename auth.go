package main

import (
	"fmt"
	"os"
	"time"
	"errors"
	"regexp"
	"github.com/google/uuid"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret []byte

// InitAuth инициализирует секретный ключ для JWT
func InitAuth() {
	jwtSecret = []byte(os.Getenv("JWT_SECRET"))
	if len(jwtSecret) < 32 {
		panic("JWT_SECRET must be at least 32 characters long")
	}
}

// HashPassword хеширует пароль с использованием bcrypt
func HashPassword(password string) (string, error) {
	// TODO: Реализуйте хеширование пароля
	//
	// Что нужно сделать:
	// 1. Импортируйте "golang.org/x/crypto/bcrypt"
	// 2. Используйте bcrypt.GenerateFromPassword()
	// 3. Передайте []byte(password) и bcrypt.DefaultCost
	// 4. Обработайте ошибку и верните результат как string
	//
	// Документация: https://pkg.go.dev/golang.org/x/crypto/bcrypt#GenerateFromPassword

    bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

    return string(bytes), err
}

// CheckPassword проверяет пароль против хеша
func CheckPassword(password, hash string) bool {
	// TODO: Реализуйте проверку пароля
	//
	// Что нужно сделать:
	// 1. Используйте bcrypt.CompareHashAndPassword()
	// 2. Передайте []byte(hash) и []byte(password)
	// 3. Верните true если ошибки нет, false если есть
	//
	// Документация: https://pkg.go.dev/golang.org/x/crypto/bcrypt#CompareHashAndPassword

	err := bcrypt.CompareHashAndPassword([]byte(password), []byte(hash))
	return  (err == nil)
}

// GenerateToken создает JWT токен для пользователя
func GenerateToken(user User) (string, error) {
	// TODO: Реализуйте генерацию JWT токена
	//
	// Что нужно сделать:
	// 1. Импортируйте "time" и "github.com/golang-jwt/jwt/v5"
	// 2. Создайте Claims структуру с данными пользователя
	//    - Заполните UserID, Email, Username
	//    - Установите ExpiresAt на 24 часа вперед: jwt.NewNumericDate(time.Now().Add(24 * time.Hour))
	//    - Установите IssuedAt на текущее время: jwt.NewNumericDate(time.Now())
	// 3. Создайте токен с помощью jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// 4. Подпишите токен с помощью token.SignedString(jwtSecret)
	//
	// Документация: https://pkg.go.dev/github.com/golang-jwt/jwt/v5

	claims := Claims{
		UserID: user.ID,
		Email: user.Email,
		Username: user.Username,
	}

	claims.RegisteredClaims = jwt.RegisteredClaims{
		ID: uuid.New().String(),
		Subject: string(user.ID),
		IssuedAt: jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)

	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateToken проверяет и парсит JWT токен
func ValidateToken(tokenString string) (*Claims, error) {
	// TODO: Реализуйте валидацию JWT токена
	//
	// Что нужно сделать:
	// 1. Создайте пустую структуру claims := &Claims{}
	// 2. Используйте jwt.ParseWithClaims() для парсинга токена
	// 3. В keyFunc проверьте, что алгоритм подписи HMAC (*jwt.SigningMethodHMAC)
	// 4. Верните jwtSecret как ключ для проверки подписи
	// 5. Проверьте, что токен валиден (token.Valid)
	// 6. Верните claims и ошибку
	//
	// Подсказка: keyFunc - это функция func(token *jwt.Token) (interface{}, error)
	
	if tokenString == "" {
		return nil, fmt.Errorf("token is empty")
	}

	claims := &Claims{}

	// Парсим токен с проверкой подписи
	token, err := jwt.ParseWithClaims(tokenString, &Claims{},
	func(token *jwt.Token) (interface{}, error) {

		// проверяем алгоритм
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return jwtSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

// ValidatePassword проверяет требования к паролю
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	// TODO: Добавьте дополнительные проверки если необходимо
	// Идеи для улучшения:
	// - проверка наличия цифр
	// - проверка наличия заглавных букв
	// - проверка наличие специальных символов

	var is_ok bool

	// Проверка наличия цифр
	is_ok, _ = regexp.MatchString(`\d`, password)
	if !is_ok {
		return errors.New("password не содержит цифр")
	}

	// Проверка наличия заглавных букв
	is_ok, _ = regexp.MatchString(`[A-Z]`, password)
	if !is_ok {
		return errors.New("password не содержит заглавных букв")
	}

	// Проверка наличия специальных символов
	pattern := `[!@#$%^&*()_+={}\[\]:;"'<>,.?/\\|~-]`
	is_ok, _ = regexp.MatchString(pattern, password)
	if !is_ok {
		return errors.New("password не содержит специальных символов")
	}

	return nil
}

// ValidateEmail проверяет формат email (базовая проверка)
func ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email is required")
	}

	// TODO: Добавьте более строгую валидацию email если необходимо
	// Можно использовать regexp.MatchString() для проверки формата
	pattern := `^\w+@\w+\.\w+$`

	is_ok, _ := regexp.MatchString(pattern, email)
	if !is_ok {
		return errors.New("email некорректно заполнен")
	}

	return nil
}
