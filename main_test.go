package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

func TestCreateTables(t *testing.T) {
	fmt.Println("\nМодульные тесты")
	time.Sleep(1 * time.Second)
	fmt.Println("\nTestCreateTables")
	fmt.Println("Тестируем создание таблиц")

	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("error opening database: %v", err)
	}
	defer db.Close()

	ctx := context.TODO()

	err = createTables(ctx, db)
	if err != nil {
		t.Fatalf("error creating tables: %v", err)
	}

	fmt.Println("Создали таблицы")

	var usersTableExists bool
	var tableName string
	err = db.QueryRowContext(ctx, "SELECT name FROM sqlite_master WHERE type='table' AND name='users'").Scan(&tableName)
	if err != nil {
		t.Fatalf("error checking users table existence: %v", err)
	}
	usersTableExists = tableName == "users"
	if !usersTableExists {
		t.Fatal("users table does not exist")
	}

	fmt.Printf("Проверяем создалась ли таблица users: %v\n", usersTableExists)

	var expressionsTableExists bool
	err = db.QueryRowContext(ctx, "SELECT name FROM sqlite_master WHERE type='table' AND name='expressions'").Scan(&tableName)
	if err != nil {
		t.Fatalf("error checking expressions table existence: %v", err)
	}
	expressionsTableExists = tableName == "expressions"
	if !expressionsTableExists {
		t.Fatal("expressions table does not exist")
	}
	fmt.Printf("Проверяем создалась ли таблица expressions: %v\n", expressionsTableExists)
	fmt.Println("Всё прошло успешно!")
	time.Sleep(5 * time.Second)
}

func TestCreateJWT(t *testing.T) {
	fmt.Println("\nТестируем создание jwt токена")
	fmt.Println("TestCreateJWT")
	user := User{
		Login:    "testUser",
		Password: "testPassword",
	}

	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("error opening database: %v", err)
	}
	defer db.Close()

	jwtString, err := CreateJWT(user)
	if err != nil {
		t.Fatalf("error creating JWT: %v", err)
	}
	fmt.Printf("Создали jwt токен с логином: %v\n", user.Login)

	if jwtString == "" {
		t.Fatal("JWT string is empty")
	}

	fmt.Printf("Получили jwt токен: %v\n", jwtString)
	claims, err := checkJWT(jwtString)
	if err != nil {
		t.Fatalf("error verifying JWT: %v", err)
	}

	if login, ok := claims.(string); ok {
		if login != user.Login {
			t.Fatalf("expected login: %s, got: %s", user.Login, login)
		}
	} else {
		t.Fatalf("expected string claims, got: %T", claims)
	}
	fmt.Println("Проверили jwt токен")
	fmt.Println("Всё прошло успешно!")
	time.Sleep(5 * time.Second)
}

func TestInsertJWT(t *testing.T) {
	fmt.Println("\nТестируем внесение jwt токена в БД")
	fmt.Println("TestInsertJWT")

	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("error opening database: %v", err)
	}
	defer db.Close()

	if err := createTables(context.TODO(), db); err != nil {
		t.Fatalf("error creating tables: %v", err)
	}
	testUser := User{Login: "testUser", Password: "testPassword", OriginPassword: "testPassword"}
	if err := insertUser(context.TODO(), db, &testUser); err != nil {
		t.Fatalf("error inserting test user: %v", err)
	}

	fmt.Printf("Внесли пользователя в базу данных, login: %v\n", testUser.Login)

	jwtString := "testJWT"

	err = insertJWT(context.TODO(), jwtString, db, testUser)
	if err != nil {
		t.Fatalf("error inserting JWT: %v", err)
	}
	fmt.Println("Внесли jwt в БД")

	var storedJWT string
	err = db.QueryRowContext(context.TODO(), "SELECT jwt FROM users WHERE login=?", testUser.Login).Scan(&storedJWT)
	if err != nil {
		t.Fatalf("error retrieving JWT from database: %v", err)
	}
	fmt.Println("Нашли токен в БД")

	if storedJWT != jwtString {
		t.Fatalf("expected JWT %s, got %s", jwtString, storedJWT)
	}
	fmt.Println("Проверили, что токены сопадают")
	fmt.Println("Всё прошло успешно!")
	time.Sleep(5 * time.Second)
}

func TestExistUser(t *testing.T) {
	fmt.Println("\nТестируем поиск существующего пользователя в БД")
	fmt.Println("TestExistUser")
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("error opening database: %v", err)
	}
	defer db.Close()

	if err := createTables(context.TODO(), db); err != nil {
		t.Fatalf("error creating tables: %v", err)
	}
	testUser := User{Login: "testUser", Password: "testPassword", OriginPassword: "testPassword"}
	if err := insertUser(context.TODO(), db, &testUser); err != nil {
		t.Fatalf("error inserting test user: %v", err)
	}

	fmt.Printf("Создали таблицы и внесли пользователя в БД, login: %v\n", testUser.Login)

	exists, err := ExistUser(context.TODO(), db, &testUser)
	if err != nil {
		t.Fatalf("error checking if user exists: %v", err)
	}

	if !exists {
		t.Fatalf("expected user to exist, but it does not")
	}

	fmt.Printf("Проверили что пользователь существует: %v\n", exists)

	nonExistentUser := User{Login: "nonExistentUser", Password: "password", OriginPassword: "password"}
	fmt.Printf("Проверим существует ли несуществующий пользователь в БД, login: %v\n", nonExistentUser.Login)
	exists, err = ExistUser(context.TODO(), db, &nonExistentUser)
	if err != nil {
		t.Fatalf("error checking if non-existent user exists: %v", err)
	}

	if exists {
		t.Fatalf("expected non-existent user to not exist, but it does")
	}
	fmt.Printf("Убедились в том, что его не существует, exist: %v\n", exists)
	fmt.Println("Всё прошло успешно!")
	time.Sleep(5 * time.Second)
}

func TestRegisterUser1(t *testing.T) {
	fmt.Println("\nТестируем регистрацию пользователя")
	fmt.Println("TestRegisterUser1")
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("error opening database: %v", err)
	}
	defer db.Close()

	if err := createTables(context.TODO(), db); err != nil {
		t.Fatalf("error creating tables: %v", err)
	}

	fmt.Println("Создали таблицы")
	var ErrUserExists = errors.New("UNIQUE constraint failed: users.login")

	testCases := []struct {
		name     string
		input    *User
		expected error
	}{
		{
			name: "Register new user",
			input: &User{
				Login:          "testUser",
				OriginPassword: "testPassword",
			},
			expected: nil,
		},
		{
			name: "Attempt to register existing user",
			input: &User{
				Login:          "testUser",
				OriginPassword: "testPassword",
			},
			expected: ErrUserExists,
		},
	}

	fmt.Println("Попробуем зарегистрировать нового и уже существующего пользователя")
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := RegisterUser(context.TODO(), db, tc.input)

			if err != nil && !strings.Contains(err.Error(), tc.expected.Error()) {
				t.Errorf("expected error containing substring: %s, got: %v", tc.expected, err)
			}
		})
	}
	fmt.Println("Нового пользователя создали, а на уже существуюшего получили сообщение")
	fmt.Println("Всё прошло успешно!")
	time.Sleep(5 * time.Second)
}

func TestInsertUser(t *testing.T) {
	fmt.Println("\nТестируем внесение пользователя в БД")
	fmt.Println("TestInsertUser")
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("error opening database: %v", err)
	}
	defer db.Close()

	if err := createTables(context.TODO(), db); err != nil {
		t.Fatalf("error creating tables: %v", err)
	}

	var ErrUserExists = errors.New("UNIQUE constraint failed: users.login")

	testCases := []struct {
		name     string
		input    *User
		expected error
	}{
		{
			name: "Insert new user",
			input: &User{
				Login:          "testUser",
				OriginPassword: "testPassword",
			},
			expected: nil,
		},
		{
			name: "Attempt to insert user with existing login",
			input: &User{
				Login:          "testUser",
				OriginPassword: "testPassword",
			},
			expected: ErrUserExists,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := insertUser(context.TODO(), db, tc.input)

			if err != nil && !strings.Contains(err.Error(), tc.expected.Error()) {
				t.Errorf("expected error: %v, got: %v", tc.expected, err)
			}
		})
	}
	fmt.Println("Нового пользователя создали, а на уже существуюшего получили сообщение")
	fmt.Println("Всё прошло успешно!")
	time.Sleep(5 * time.Second)
}

func TestGenerate(t *testing.T) {
	fmt.Println("\nТестируем хэширование пароля")
	fmt.Println("TestGenerate")
	testCases := []struct {
		name          string
		inputPassword string
		expectedError bool
	}{
		{
			name:          "Valid password",
			inputPassword: "testPassword",
			expectedError: false,
		},
		{
			name:          "Empty password",
			inputPassword: "",
			expectedError: false,
		},
	}

	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("error opening database: %v", err)
	}
	defer db.Close()

	if err := createTables(context.TODO(), db); err != nil {
		t.Fatalf("error creating tables: %v", err)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hash, err := generate(tc.inputPassword)

			if tc.expectedError {
				if err == nil {
					t.Error("expected error, but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, but got: %v", err)
				}
			}

			if !tc.expectedError && hash == "" {
				t.Error("expected non-empty hash")
			}
			fmt.Printf("Password: %v, hash: %v\n", tc.inputPassword, hash)
		})
	}
	fmt.Println("Всё прошло успешно!")
	time.Sleep(5 * time.Second)
}

func TestComparePassword(t *testing.T) {
	fmt.Println("\nТестируем сравнение хэшэй паролей")
	fmt.Println("TestComparePassword")
	// Создаем фиктивного пользователя
	u := User{
		OriginPassword: "secret123",
	}

	// Хешируем пароль
	hash, err := bcrypt.GenerateFromPassword([]byte(u.OriginPassword), bcrypt.DefaultCost)
	if err != nil {
		t.Errorf("ошибка при хешировании пароля: %v", err)
	}

	// Создаем второго пользователя с тем же паролем
	u2 := User{
		Password: string(hash),
	}

	fmt.Printf("Хэшируем пароль: %v, hash: %v\n", u.OriginPassword, u2.Password)

	// Сравниваем пароли
	match, err := u.ComparePassword(u2)
	if err != nil {
		t.Errorf("ошибка при сравнении паролей: %v", err)
	}

	// Проверяем, совпадают ли пароли
	if !match {
		t.Errorf("ожидалось, что пароли совпадают, но они не совпадают")
	}
	fmt.Printf("Сравнение: %v\n", match)
	fmt.Println("Всё прошло успешно!")
	time.Sleep(5 * time.Second)
}

func TestAuthorization1(t *testing.T) {
	fmt.Println("\nТестируем авторизацию")
	fmt.Println("TestAuthorization1")

	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Error connecting to the database: %v", err)
	}
	defer db.Close()

	defer func() {
		if _, err := db.Exec("DROP TABLE IF EXISTS users"); err != nil {
			t.Fatalf("Error dropping users table: %v", err)
		}
	}()

	ctx := context.TODO()
	if err := createTables(ctx, db); err != nil {
		t.Fatalf("Error creating tables: %v", err)
	}

	testUser := User{
		Login:          "test_user",
		OriginPassword: "test_password",
	}

	if err := RegisterUser(ctx, db, &testUser); err != nil {
		t.Fatalf("Error registering test user: %v", err)
	}

	fmt.Printf("Регистрируем пользователя, login: %v, password: %v\n", testUser.Login, testUser.OriginPassword)

	jwt, success, err := Authorization(ctx, db, testUser)
	if err != nil {
		t.Fatalf("Error during authorization: %v", err)
	}
	if !success {
		t.Fatalf("Authorization failed unexpectedly")
	}
	if jwt == "" {
		t.Fatalf("JWT token not returned")
	}

	fmt.Printf("Авторизовались под правильным паролем(%v) и получили токен: %v\n", testUser.OriginPassword, jwt)

	testUser.OriginPassword = "incorrect_password"
	_, success, err = Authorization(ctx, db, testUser)
	if err != nil {
		t.Fatalf("Error during authorization: %v", err)
	}
	if success {
		t.Fatalf("Authorization succeeded unexpectedly")
	}

	fmt.Printf("Попробуем авторизоваться под неправильным паролем, login: %v, password: %v\n success: %v\n", testUser.Login, testUser.OriginPassword, success)
	nonExistentUser := User{
		Login:          "non_existent_user",
		OriginPassword: "test_password",
	}
	_, success, err = Authorization(ctx, db, nonExistentUser)
	if err != nil {
		t.Fatalf("Error during authorization: %v", err)
	}
	if success {
		t.Fatalf("Authorization succeeded unexpectedly for non-existent user")
	}
	fmt.Printf("Авторизовываемся как несуществующий пользователь, login: %v, password: %v\n", nonExistentUser.Login, nonExistentUser.OriginPassword)
	fmt.Printf("success: %v\n", success)
	fmt.Println("Всё прошло успешно!")
	time.Sleep(5 * time.Second)
}

func TestValidateExpression(t *testing.T) {
	fmt.Println("\nТестируем валидность выражения")
	fmt.Println("TestValidateExpression")
	tests := []struct {
		expression   string
		expectedOp   string
		expectedPass bool
		expectedErr  bool
	}{
		{"2+3", "+", true, false},
		{"5*6", "*", true, false},
		{"8/2", "/", true, false},
		{"10", "", false, false},
		{"$10", "", false, true},
		{"10€", "", false, true},
		{"10$", "", false, true},
		{"10¥", "", false, true},
		{"10£", "", false, true},
		{"10$", "", false, true},
		{"10*5+3", "", false, false},
	}

	fmt.Println("Начинаем тестирование")
	for _, test := range tests {
		op, pass, err := validateExpression(test.expression)

		fmt.Printf("\nИсходно, expression: %v, expectedOp: %v, expectedPass: %v, expectedErr: %v\n", test.expression, test.expectedOp, test.expectedPass, test.expectedErr)
		if op != test.expectedOp {
			t.Errorf("Expression: %s, expected operator: %s, got: %s", test.expression, test.expectedOp, op)
		}

		if pass != test.expectedPass {
			t.Errorf("Expression: %s, expected pass: %t, got: %t", test.expression, test.expectedPass, pass)
		}

		if (err != nil) != test.expectedErr {
			t.Errorf("Expression: %s, expected error: %t, got: %t", test.expression, test.expectedErr, err != nil)
		}
		fmt.Printf("expression: %v, operation: %v, correct: %v, error: %v\n", test.expression, op, pass, err)
	}
	fmt.Println("Всё прошло успешно!")
	time.Sleep(5 * time.Second)
}

func TestTimeOperation(t *testing.T) {
	fmt.Println("\nТестируем возврат времени исполнения нужной операции")
	fmt.Println("TestTimeOperation")
	operations := []Operation{
		{Name: "+", Duration: 5},
		{Name: "-", Duration: 10},
		{Name: "*", Duration: 15},
		{Name: "/", Duration: 20},
	}

	tests := []struct {
		operations []Operation
		operator   string
		expected   int
	}{
		{operations, "+", 5},
		{operations, "-", 10},
		{operations, "*", 15},
		{operations, "/", 20},
		{operations, "%", 0},
	}

	fmt.Println("Начинаем тестирование")
	for _, test := range tests {
		fmt.Printf("operator: %v, Expduration: %v\n", test.operator, test.expected)
		result := TimeOperation(test.operations, test.operator)
		if result != test.expected {
			t.Errorf("For operator %s, expected: %d, got: %d", test.operator, test.expected, result)
		}
	}
	fmt.Println("Всё прошло успешно!")
	time.Sleep(5 * time.Second)
}

func TestCalcExpression(t *testing.T) {
	fmt.Println("\nТестируем вычисление выражения")
	fmt.Println("TestCalcExpression")
	// Тест с корректным выражением
	expression := "2 + 2"
	expectedResult := "4"
	result, err := CalcExpression(expression)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result != expectedResult {
		t.Errorf("Expected result: %s, but got: %s", expectedResult, result)
	}
	fmt.Printf("expression: %v, ExpResult: %v, result: %v\n", expression, expectedResult, result)

	// Тест с некорректным выражением
	invalidExpression := "2 +"
	_, err = CalcExpression(invalidExpression)
	if err == nil {
		t.Error("Expected error, but got nil")
	}
	fmt.Println("Тестируем неправильное выражение")
	fmt.Printf("invalidExpression: %v, result: %v\n", invalidExpression, err)

	// Тест с делением на ноль
	expressionDivByZero := "1 / 0"
	_, err = CalcExpression(expressionDivByZero)
	expectedErrorMessage := fmt.Sprintf("division by zero: %v", expressionDivByZero)
	if err == nil || err.Error() != expectedErrorMessage {
		t.Errorf("Expected error message: %s, but got: %v", expectedErrorMessage, err)
	}
	fmt.Println("Тестируем деление на ноль")
	fmt.Printf("expressionDivByZero: %v, result: %v\n", expressionDivByZero, err)

	fmt.Println("Всё прошло успешно!")
	time.Sleep(5 * time.Second)
}

func TestCheckJWT(t *testing.T) {
	fmt.Println("\nТестируем проверку jwt токена")
	fmt.Println("TestCheckJWT")
	// Создаем тестовый JWT токен
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"name": "testuser",
		"nbf":  time.Now().Unix(),
		"exp":  time.Now().Add(5 * time.Minute).Unix(),
		"iat":  time.Now().Unix(),
	})
	tokenString, err := token.SignedString([]byte("super_secret_signature"))
	if err != nil {
		t.Fatalf("Failed to sign JWT token: %v", err)
	}
	fmt.Println("Делаем токен\n name: testuser, sign: super_secret_signature")

	// Вызываем функцию checkJWT с тестовым JWT токеном
	username, err := checkJWT(tokenString)

	// Проверяем, что ошибка отсутствует
	if err != nil {
		t.Fatalf("checkJWT returned error: %v", err)
	}
	fmt.Println("Проверяем токен и получаем username")

	// Проверяем, что возвращенное имя пользователя соответствует ожидаемому
	expectedUsername := "testuser"
	if username != expectedUsername {
		t.Fatalf("Expected username to be %s, but got %s", expectedUsername, username)
	}
	fmt.Printf("username: %v, expectedUsername: %v\n", username, expectedUsername)
	fmt.Println("Всё прошло успешно!")
	time.Sleep(5 * time.Second)
}

func TestGenerateID(t *testing.T) {
	fmt.Println("\nТестируем генерацию ID")
	fmt.Println("TestGenerateID")
	id := generateID()

	if id == "" {
		t.Errorf("Expected non-empty ID, got empty string")
	}

	fmt.Printf("ID: %v\n", id)
	fmt.Println("Всё прошло успешно!")
	time.Sleep(5 * time.Second)
}

func TestUpPing(t *testing.T) {
	fmt.Println("\nТестируем время пинга сервера")
	fmt.Println("TestUpPing")
	ping := Ping{}
	upPing(&ping)

	// Проверяем, что поле lastPing не пустое
	if ping.lastPing == "" {
		t.Errorf("Expected lastPing to be non-empty, got empty string")
	}

	fmt.Println("Обновляем пинг, ExpFormat: 2006-01-02 15:04:05")
	// Проверяем формат времени
	_, err := time.Parse("2006-01-02 15:04:05", ping.lastPing)
	if err != nil {
		t.Errorf("Expected lastPing to be in format '2006-01-02 15:04:05', got: %s", ping.lastPing)
	}
	fmt.Println("Всё прошло успешно!")
	time.Sleep(5 * time.Second)
	fmt.Println("Конец модульных тестов")
}

func TestDistributeExpression(t *testing.T) {
	fmt.Println("\nИнтеграционные тесты")
	fmt.Println("\nTestDistributeExpression")
	time.Sleep(1 * time.Second)
	fmt.Println("Тестируем добавление выражения")
	ctx := context.TODO()
	db, err := sql.Open("sqlite3", "test.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err := createTables(ctx, db); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Создаём базу данных test.db")

	user := User{
		Login:          "test_user",
		OriginPassword: "test_password",
	}

	if err := RegisterUser(ctx, db, &user); err != nil {
		t.Errorf("Failed to register user: %v", err)
	}

	fmt.Println("Регистрируем пользователя с лоигном: test_user и паролем: test_password")
	expression := Expression{
		Expression: "2+2",
		LoginUser:  "test_user",
		db:         db,
		operations: []Operation{
			{Name: "+", Duration: 5},
			{Name: "-", Duration: 10},
			{Name: "*", Duration: 15},
			{Name: "/", Duration: 20},
		},
		ctx: context.TODO(),
	}

	express, id, err := DistributeExpression(expression)
	if err != nil {
		t.Errorf("Failed to distribute expression: %v", err)
	}

	fmt.Println("Добавляем выражение 2+2")
	if id == "" {
		t.Errorf("Expression ID is empty")
	}

	fmt.Printf("Проверяем id выражения: %v", id)

	if express != "2+2" {
		t.Errorf("Expected expression: 2+2, got: %s", express)
	}

	time.Sleep(2 * time.Second)

	expressions, err := SearchExpressionByID(ctx, db, "test_user", id)
	if err != nil {
		t.Errorf("Failed to search expression by ID: %v", err)
	}

	fmt.Println("\nИщем выражение в базе данных")

	if len(expressions) == 0 {
		t.Error("Expression not found")
	}

	exp := expressions[0]

	if exp.Status != "выполнено" {
		t.Errorf("Expected expression status: выполнено, got: %s", exp.Status)
	}

	fmt.Printf("Проверяем статус выражения: %v\n", exp.Status)

	_, err = db.ExecContext(ctx, "DELETE FROM users WHERE login=?", "test_user")
	if err != nil {
		t.Errorf("Failed to delete test user: %v", err)
	}
	fmt.Println("Всё прошло успешно!")
	time.Sleep(5 * time.Second)
}

func TestRegisterUser(t *testing.T) {
	fmt.Println("\nТестируем регистрацию")
	fmt.Println("TestRegisterUser")
	ctx := context.TODO()
	db, err := sql.Open("sqlite3", "test.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err := createTables(ctx, db); err != nil {
		log.Fatal(err)
	}

	user := User{
		Login:          "test_user",
		OriginPassword: "test_password",
	}

	err = RegisterUser(ctx, db, &user)
	if err != nil {
		t.Errorf("Failed to register user: %v", err)
	}

	fmt.Println("Регистриурем пользователя с логином: test_user и паролем: test_password")

	exist, err := ExistUser(ctx, db, &user)
	if err != nil {
		t.Errorf("Error checking user existence: %v", err)
	}
	if !exist {
		t.Error("User not found after registration")
	}

	fmt.Printf("Проверяем существует ли добавленный пользователь в базе данных: %v\n", exist)
	_, err = db.ExecContext(ctx, "DELETE FROM users WHERE login=?", "test_user")
	if err != nil {
		t.Errorf("Failed to delete test user: %v", err)
	}
	fmt.Println("Всё прошло успешно!")
	time.Sleep(5 * time.Second)
}

func TestAuthorization(t *testing.T) {
	fmt.Println("\nТестируем авторизацию")
	fmt.Println("TestAuthorization")
	ctx := context.TODO()
	db, err := sql.Open("sqlite3", "test.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err := createTables(ctx, db); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Создали базу данных")
	user := User{
		Login:          "test_user",
		OriginPassword: "test_password",
	}

	if err := RegisterUser(ctx, db, &user); err != nil {
		t.Errorf("Failed to register user: %v", err)
	}

	fmt.Println("Регистрируем пользователя с логином: test_user и паролем: test_password")

	jwt, result, err := Authorization(ctx, db, user)
	if err != nil {
		t.Errorf("Authorization error: %v", err)
	}
	if !result {
		t.Error("Authorization failed")
	}
	if jwt == "" {
		t.Error("JWT token is empty")
	}

	fmt.Printf("Проверяем авторизацию пользователя и выдачу jwt токена: %v\n", jwt)
	_, err = db.ExecContext(ctx, "DELETE FROM users WHERE login=?", "test_user")
	if err != nil {
		t.Errorf("Failed to delete test user: %v", err)
	}
	fmt.Println("Всё прошло успешно!")
	fmt.Println("\nКонец теста")
}
