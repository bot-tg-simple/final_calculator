Это схема программы:

#### Structs:

**User**:

Login: string
Password: string
OriginPassword: string
JWT: string


**Expression**: 

ID: string
Expression: string
LoginUser: string
Status: string
CreatedAt: time.Time
UpdatedAt: time.Time
Result: string
ctx: context.Context
db: *sql.DB
operations: []Operation
resultChannel: chan string
updateChannel: chan string
durationChannel: chan int


**Operation**:

Name: string
Duration: int
StartTime: time.Time
Status: string


**Calculate**:

Expression: *Expression
Operation: *Operation


**Ping**:

lastPing: string


### Methods:

*createTables(ctx context.Context, db sql.DB) error:
Создает таблицы в базе данных.

CreateJWT(u User) (string, error):
Создает JWT-токен для пользователя.

*insertJWT(ctx context.Context, jwt string, db sql.DB, u User) error:
Вставляет JWT-токен в базу данных для пользователя.

ExistUser(ctx context.Context, db *sql.DB, user *User) (bool, error):
Проверяет, существует ли пользователь в базе данных.

**RegisterUser(ctx context.Context, db sql.DB, user User) error:
Регистрирует нового пользователя в базе данных.

generate(s string) (string, error):
Генерирует хэш пароля.

compare(hash string, s string) error:
Сравнивает хэш пароля с паролем пользователя.

Authorization(ctx context.Context, db *sql.DB, u User) (string, bool, error):
Проверяет подлинность пользователя и возвращает JWT-токен.

validateExpression(expression string) (string, bool, error):
Проверяет корректность выражения.

TimeOperation(operations []Operation, operator string) int:
Возвращает время выполнения операции.

CalcExpression(expression string) (string, error):
Вычисляет результат выражения.

checkJWT(tokenString string) (interface{}, error):
Проверяет JWT-токен.

DistributeExpression(e Expression) (string, string, error):
Распределяет выражение на выполнение.

insertExpression(e Expression) error:
Вставляет выражение в базу данных.

updateExpression(e Expression, result string, status string) error:
Обновляет статус и результат выполнения выражения в базе данных.

SearchExpressionByID(ctx context.Context, db *sql.DB, login string, id string) ([]Expression, error):
Получает выражение по ID из базы данных.

SearchExpressions(ctx context.Context, db *sql.DB, login string) ([]Expression, error):
Получает все выражения из базы данных.

upPing(ping *Ping):
Обновляет время последнего пинга.


### API Endpoints:

1. **POST /expression**:
Добавляет новое выражение для выполнения.

2. **POST /id-expression**:
Получает конкретное выражение по ID.

3. **POST /expressions**:
Получает все выражения.

4. **GET /operations**:
Получает список операций.

5. **POST /duration**:
Обновляет длительность операции.

6. **POST /register**:
Регистрирует нового пользователя.

7. **POST /login**:
Авторизует пользователя и выдает JWT токен.

8. **GET /ping**:
Проверяет соединение с сервером и обновляет время последнего пинга.

9. **GET /workers**:
Мониторинг воркеров.

### Server:

**Server**:
Запускает сервер на порту 8080 и обрабатывает все API-запросы.
