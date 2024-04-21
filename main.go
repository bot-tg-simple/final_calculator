package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Knetic/govaluate"
	_ "github.com/Knetic/govaluate"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type (
	User struct {
		Login          string
		Password       string
		OriginPassword string
		JWT            string
	}

	Expression struct {
		ID              string
		Expression      string
		LoginUser       string
		Status          string
		CreatedAt       time.Time
		UpdatedAt       time.Time
		Result          string
		ctx             context.Context
		db              *sql.DB
		operations      []Operation
		resultChannel   chan string
		updateChannel   chan string
		durationChannel chan int
	}

	Operation struct {
		Name      string
		Duration  int
		StartTime time.Time
		Status    string
	}

	Calculate struct {
		Expression *Expression
		Operation  *Operation
	}

	Ping struct {
		lastPing string
	}
)

const hmacSampleSecret = "super_secret_signature"

var (
	expressionMap = make(map[string]chan string)
	updateMap     = make(map[string]chan string)
	durationMap   = make(map[string]chan int)
	mutex         sync.Mutex
)

func createTables(ctx context.Context, db *sql.DB) error {
	const (
		usersTable = `
            CREATE TABLE IF NOT EXISTS users( 
                login TEXT UNIQUE NOT NULL,  
                password TEXT NOT NULL, 
                jwt TEXT 
            );`

		expressionsTable = `
            CREATE TABLE IF NOT EXISTS expressions(
                id TEXT PRIMARY KEY, 
                expression TEXT NOT NULL,
                login_user INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL,
                result REAL NULL
            );`
	)

	if _, err := db.ExecContext(ctx, usersTable); err != nil {
		return err
	}

	if _, err := db.ExecContext(ctx, expressionsTable); err != nil {
		return err
	}

	return nil
}

func CreateJWT(u User) (string, error) {
	const hmacSampleSecret = "super_secret_signature"
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"name": u.Login,
		"nbf":  now.Unix(),
		"exp":  now.Add(5 * time.Minute).Unix(),
		"iat":  now.Unix(),
	})

	tokenString, err := token.SignedString([]byte(hmacSampleSecret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func insertJWT(ctx context.Context, jwt string, db *sql.DB, u User) error {
	var q = `UPDATE users SET jwt = $1 WHERE login= $2`
	_, err := db.ExecContext(ctx, q, jwt, u.Login)
	if err != nil {
		return err
	}
	return nil
}

func ExistUser(ctx context.Context, db *sql.DB, user *User) (bool, error) {
	var q = `SELECT login FROM users WHERE login=?`
	rows, err := db.QueryContext(ctx, q, user.Login)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var login string
		if err := rows.Scan(&login); err != nil {
			return false, err
		}
		if login == user.Login {
			return true, nil
		}
	}

	return false, nil
}

func RegisterUser(ctx context.Context, db *sql.DB, user *User) error {
	password, err := generate(user.OriginPassword)
	if err != nil {
		return err
	}
	user.Password = password
	insert := insertUser(ctx, db, user)
	if insert != nil {
		return insert
	}
	return nil
}

func insertUser(ctx context.Context, db *sql.DB, user *User) error {
	var q = `INSERT INTO users (login, password) values ($1, $2)`
	_, err := db.ExecContext(ctx, q, user.Login, user.Password)
	if err != nil {
		return err
	}
	return nil
}

func generate(s string) (string, error) {
	saltedBytes := []byte(s)
	hashedBytes, err := bcrypt.GenerateFromPassword(saltedBytes, bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	hash := string(hashedBytes[:])
	return hash, nil
}

func compare(hash string, s string) error {
	incoming := []byte(s)
	existing := []byte(hash)
	return bcrypt.CompareHashAndPassword(existing, incoming)
}

func (u User) hashPassword(db *sql.DB, u2 User) (string, error) {
	var hash string
	err := db.QueryRow("SELECT password FROM users WHERE login = ?", u2.Login).Scan(&hash)
	if err != nil {
		return "", err
	}
	return hash, nil
}

func (u User) ComparePassword(u2 User) (bool, error) {
	err := compare(u2.Password, u.OriginPassword)
	if err != nil {
		return false, nil
	}
	return true, nil
}

func Authorization(ctx context.Context, db *sql.DB, u User) (string, bool, error) {
	exist, err := ExistUser(ctx, db, &u)
	if err != nil {
		return "", false, err
	}
	if !exist {
		return "", false, nil
	}
	password, err := u.hashPassword(db, u)
	if err != nil {
		return "", false, err
	}
	u.Password = password
	result, err := u.ComparePassword(u)
	if err != nil {
		return "", false, err
	}
	if !result {
		return "", false, nil
	}
	jwt, err := CreateJWT(u)
	if err != nil {
		return "", false, err
	}
	insert := insertJWT(ctx, jwt, db, u)
	if insert != nil {
		return "", false, insert
	}
	return jwt, true, nil
}

func validateExpression(expression string) (string, bool, error) {
	if strings.ContainsAny(expression, "$€£¥") {
		return "", false, fmt.Errorf("invalid expression: contains currency symbols")
	}

	operators := []string{"+", "-", "*", "/"}
	operatorCount := 0
	for _, op := range operators {
		if strings.Contains(expression, op) {
			operatorCount++
		}
	}

	if operatorCount != 1 {
		return "", false, nil
	}

	operator := ""
	for _, op := range operators {
		if strings.Contains(expression, op) {
			operator = op
			break
		}
	}

	return operator, true, nil
}

func TimeOperation(operations []Operation, operator string) int {
	for i := range operations {
		if operations[i].Name == operator {
			return operations[i].Duration
		}
	}
	return 0
}

func CalcExpression(expression string) (string, error) {
	expr, err := govaluate.NewEvaluableExpression(expression)
	if err != nil {
		return "", err
	}

	result, err := expr.Evaluate(nil)
	if err != nil {
		if strings.Contains(err.Error(), "division by zero") {
			return "", fmt.Errorf("division by zero: %s", expression)
		}
		return "", err
	}

	switch v := result.(type) {
	case float64:
		if math.IsInf(v, 0) {
			return "", fmt.Errorf("division by zero: %s", expression)
		}
		return fmt.Sprintf("%v", result), nil
	default:
		return "", fmt.Errorf("invalid result type")
	}
}

func checkJWT(tokenString string) (interface{}, error) {
	tokenFromString, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return "", fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(hmacSampleSecret), nil
	})

	if err != nil {
		return "", err
	}

	if claims, ok := tokenFromString.Claims.(jwt.MapClaims); ok {
		return claims["name"], nil
	} else {
		return "", err
	}
}

func DistributeExpression(e Expression) (string, string, error) {
	operator, simple, err := validateExpression(e.Expression)
	if err != nil {
		return e.Expression, "", err
	}

	mutex.Lock()
	defer mutex.Unlock()

	id := generateID()
	e.ID = id
	e.resultChannel = make(chan string)
	e.updateChannel = make(chan string)
	e.durationChannel = make(chan int)
	expressionMap[e.ID] = e.resultChannel
	updateMap[e.ID] = e.updateChannel
	durationMap[e.ID] = e.durationChannel

	insert := insertExpression(e)
	if insert != nil {
		return e.Expression, "", insert
	}

	var status string
	var result string

	// Возвращаем ответ сразу же, не дожидаясь выполнения операции
	go func() {
		if simple {
			duration := TimeOperation(e.operations, operator)
			e.durationChannel <- duration
		} else {
			e.durationChannel <- -1
		}
	}()

	result, err = CalcExpression(e.Expression)
	if err != nil {
		status = "не выполнено"
	} else {
		status = "выполнено"
	}

	go func() {
		update := updateExpression(e, result, status)
		if update != nil {
			log.Println("err update ")
		}
	}()

	return e.Expression, e.ID, nil
}

func generateID() string {
	id := uuid.New().String()
	return id
}

func insertExpression(e Expression) error {
	timing := time.Now()
	var q = `INSERT INTO expressions (id, expression, login_user, status, created_at, updated_at)  values (?, ?, ?, ?, ?, ?)`
	_, err := e.db.ExecContext(e.ctx, q, e.ID, e.Expression, e.LoginUser, "выполняется", timing, timing)
	if err != nil {
		return err
	}
	return nil
}

func updateExpression(e Expression, result string, status string) error {
	var q = `UPDATE expressions SET result=$1, status=$2, updated_at=$3 WHERE id=$4`
	_, err := e.db.ExecContext(e.ctx, q, result, status, time.Now(), e.ID)
	if err != nil {
		return err
	}
	return nil
}

func SearchExpressionByID(ctx context.Context, db *sql.DB, login string, id string) ([]Expression, error) {
	expressions := []Expression{}
	var q = `
	SELECT id, expression, login_user, status, 
	created_at, updated_at, result FROM expressions WHERE login_user=? AND id=?
	`
	rows, err := db.QueryContext(ctx, q, login, id)
	if err != nil {
		return expressions, err
	}
	defer rows.Close()

	for rows.Next() {
		var exp Expression
		var result sql.NullString // Используем sql.NullString для обработки NULL
		err := rows.Scan(&exp.ID, &exp.Expression, &exp.LoginUser, &exp.Status, &exp.CreatedAt, &exp.UpdatedAt, &result)
		if err != nil {
			return expressions, err
		}
		if result.Valid { // Проверяем, является ли значение не NULL
			exp.Result = result.String // Присваиваем строковое значение только в случае, если оно не NULL
		}
		expressions = append(expressions, exp)
	}

	return expressions, nil
}

func upPing(ping *Ping) {
	t := time.Now() // Получаем текущее время
	formattedTime := t.Format("2006-01-02 15:04:05")
	ping.lastPing = formattedTime
}

func SearchExpressions(ctx context.Context, db *sql.DB, login string) ([]Expression, error) {
	expressions := []Expression{}
	var q = `
	SELECT id, expression, login_user, status, 
	created_at, updated_at, result FROM expressions WHERE login_user=?
	`
	rows, err := db.QueryContext(ctx, q, login)
	if err != nil {
		return expressions, err
	}
	defer rows.Close()

	for rows.Next() {
		var exp Expression
		err := rows.Scan(&exp.ID, &exp.Expression, &exp.LoginUser, &exp.Status, &exp.CreatedAt, &exp.UpdatedAt, &exp.Result)
		if err != nil {
			return expressions, err
		}
		expressions = append(expressions, exp)
	}

	return expressions, nil
}

func main() {
	ctx := context.TODO()

	db, err := sql.Open("sqlite3", "store.db")
	if err != nil {
		panic(err)
	}

	if err = createTables(ctx, db); err != nil {
		panic(err)
	}

	router := gin.Default()

	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST"},
		AllowHeaders:     []string{"Origin"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	operations := []Operation{
		{Name: "+", Duration: 5},
		{Name: "-", Duration: 10},
		{Name: "*", Duration: 15},
		{Name: "/", Duration: 20},
	}

	t := time.Now() // Получаем текущее время
	formattedTime := t.Format("2006-01-02 15:04:05")

	ping := Ping{
		lastPing: formattedTime,
	}

	router.POST("/expression", func(ctx *gin.Context) {
		upPing(&ping)
		expression := ctx.PostForm("expression")
		jwt := ctx.PostForm("jwt")
		check, err := checkJWT(jwt)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"expression": err})
			return
		}
		checkStr := fmt.Sprintf("%v", check)
		data := &Expression{
			Expression: expression,
			LoginUser:  checkStr,
			db:         db,
			operations: operations,
			ctx:        ctx,
		}
		express, id, err := DistributeExpression(*data)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "expression": express})
			return
		}

		var approximateTime int
		operator, _, err := validateExpression(expression)
		if err == nil {
			approximateTime = TimeOperation(operations, operator)
		}

		ctx.JSON(http.StatusAccepted, gin.H{"expression": express, "id": id, "status": "выполняется", "approximate_time": approximateTime})
	})

	router.POST("/id-expression", func(ctx *gin.Context) {
		upPing(&ping)
		id := ctx.PostForm("id")
		jwt := ctx.PostForm("jwt")
		check, err := checkJWT(jwt)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"expression": err})
			return
		}
		login := fmt.Sprintf("%v", check)
		expressions, err := SearchExpressionByID(ctx, db, login, id)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"expression": err})
			return
		}

		if len(expressions) == 0 {
			ctx.JSON(http.StatusNotFound, gin.H{"message": "Expression not found"})
			return
		}

		exp := expressions[0]
		ctx.JSON(http.StatusOK, gin.H{
			"id":         exp.ID,
			"expression": exp.Expression,
			"login":      exp.LoginUser,
			"status":     exp.Status,
			"created_at": exp.CreatedAt,
			"updated_at": exp.UpdatedAt,
			"result":     exp.Result,
		})
	})

	router.POST("/expressions", func(ctx *gin.Context) {
		upPing(&ping)
		jwt := ctx.PostForm("jwt")
		check, err := checkJWT(jwt)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": err})
			return
		}
		login := fmt.Sprintf("%v", check)
		expressions, err := SearchExpressions(ctx, db, login)
		if err != nil {
			fmt.Println(err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err})
			return
		}

		if len(expressions) == 0 {
			ctx.JSON(http.StatusNotFound, gin.H{"message": "Expression not found"})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{"expressions": expressions})
	})

	router.GET("/operations", func(ctx *gin.Context) {
		upPing(&ping)
		ctx.JSON(http.StatusOK, gin.H{"operations": operations})
	})

	router.POST("/duration", func(ctx *gin.Context) {
		upPing(&ping)
		operation := ctx.PostForm("operation")
		duration := ctx.PostForm("duration")

		for i, op := range operations {
			if op.Name == operation {
				newDuration, err := strconv.Atoi(duration)
				if err != nil {
					ctx.JSON(http.StatusBadRequest, gin.H{"message": "Неверный формат продолжительности"})
					return
				}
				operations[i].Duration = newDuration
				ctx.JSON(http.StatusOK, gin.H{"message": "Продолжительность обновлена", "operations": operations})
				return
			}
		}

		ctx.JSON(http.StatusNotFound, gin.H{"message": "Операция не найдена"})
	})

	router.POST("/register", func(ctx *gin.Context) {
		upPing(&ping)
		login := ctx.PostForm("login")
		password := ctx.PostForm("password")
		if login == "" || password == "" {
			ctx.JSON(http.StatusBadRequest, gin.H{"message": "Login and password should not be empty!"})
			return
		}
		user := &User{
			Login:          login,
			OriginPassword: password,
		}
		exist, err := ExistUser(ctx, db, user)
		if err != nil {
			return
		}
		if exist {
			ctx.JSON(http.StatusConflict, gin.H{"message": "user with this username already exists"})
			return
		}
		result := RegisterUser(ctx, db, user)
		if result != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": result})
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"message": "Successfully!"})
	})

	router.POST("/login", func(ctx *gin.Context) {
		upPing(&ping)
		login := ctx.PostForm("login")
		password := ctx.PostForm("password")
		if login == "" || password == "" {
			ctx.JSON(http.StatusBadRequest, gin.H{"authentication": "Login and password should not be empty!"})
			return
		}
		user := &User{
			Login:          login,
			OriginPassword: password,
		}
		jwt, result, err := Authorization(ctx, db, *user)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"authentication": err})
			return
		}
		if !result {
			ctx.JSON(http.StatusUnauthorized, gin.H{"authentication": "Incorrect password or login"})
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"authentication": "Successfully authentication!", "JWT": jwt})
	})

	router.GET("/ping", func(c *gin.Context) {
		info := fmt.Sprintf("%v", ping.lastPing)
		c.JSON(http.StatusOK, gin.H{"info": info})
		upPing(&ping)
	})

	router.GET("/workers", func(ctx *gin.Context) {
		upPing(&ping)
		expressionsInfo := make(map[string]int)
		for id, durationChannel := range durationMap {
			select {
			case duration := <-durationChannel:
				expressionsInfo[id] = duration
			default:
				expressionsInfo[id] = -1
			}
		}
		ctx.JSON(http.StatusOK, gin.H{"expressions": expressionsInfo})
	})

	router.Run(":8080")
}
