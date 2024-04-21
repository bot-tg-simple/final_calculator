const input_id = document.getElementById("expressInput");
const info = document.querySelector(".expression");
const results = document.querySelector(".results")

input_id.addEventListener("keydown", function(e) {
    if (e.key === "Enter") {
        const id = input_id.value;
        if (id === '') {

            return;
        }

        let jwt = GetJWT();

        if (jwt === '') {
            info.innerHTML = `<div class="result error">
            <span class="status-icon"></span>
            <span class="expression">Вы не авторизованы</span>
            </div>`
            return
        }
        
        fetch(`http://localhost:8080/id-expression`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                id: id,
                jwt: jwt
            }),
        })
        .then((response) => {
            if (response.status === 401) {
                results.innerHTML = `<div class="result error">
                <span class="status-icon"></span>
                <span class="expression">Вы не авторизованы</span>
                </div>`
                return
            } else if (response.status === 500) {
                results.innerHTML = `<div class="result error">
                <span class="status-icon"></span>
                <span class="expression">Ошибка сервера :(</span>
                </div>`
            } else if (response.status === 404) {
                results.innerHTML = `<div class="result error">
                <span class="status-icon"></span>
                <span class="expression">Выражение с id: ${id} не было найдено :(</span>
                </div>`
            }
            else {
                return response.json()
            }
        })
        .then((data) => {

            //const expressionText = data.expression.Expression.replace(/%2B/g, '+');

            info.innerHTML = ''; // Очищаем содержимое элемента перед добавлением новой информации
            info.innerHTML = `ID: ${data.id}<br>
            Expression: ${data.expression}<br>
            Status: ${data.status}<br>
            CreatedAt: ${data.created_at}<br>
            UpdatedAt: ${data.updated_at}<br>
            Result: ${data.result}<br>
            LoginUser: ${data.login}`;

            input_id.value = '';
        })
        .catch((error) => {
            console.error('Error:', error);
        });
    }
});


function GetJWT() {
    return localStorage.getItem('jwt');
}
