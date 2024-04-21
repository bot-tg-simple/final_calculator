const form = document.getElementById("expressionForm");
const input_express = document.getElementById("expressInput");
const results = document.querySelector(".results");

form.addEventListener("submit", function(e) {
    e.preventDefault(); // Предотвращаем стандартное действие браузера

    let expression = input_express.value;

    if (expression === '') {
        return;
    }

    let jwt = GetJWT();
    if (jwt == '') {
        results.innerHTML += `<div class="result error">
        <span class="status-icon"></span>
        <span class="expression">Вы не авторизованы</span>
        </div>`
        return
    }
    // Кодирование всей строки expression перед отправкой
    expression = encodeURIComponent(expression);
    
    fetch('http://localhost:8080/expression', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
            expression: expression,
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
        } else if (response.status === 400) {
            results.innerHTML = `<div class="result error">
            <span class="status-icon"></span>
            <span class="expression">Ошибка разбора выражения: ${response.data.error}\n ${expression}</span>
            </div>`
            return
        } 
        else {
            return response.json()
        }
    })
    .then((data) => {
        console.log('Expression ID:', data.id);
        results.innerHTML += `<div class="result success">
            <span class="status-icon"></span>
            <span class="expression">${expression}<br>id: ${data.id}<br>${data.status}<br>~ ${data.approximate_time}</span>
        </div>`;
    })
    .catch((error) => {
        console.error('Error:', error);
    });

    // Очистка поля ввода после отправки
    input_express.value = '';
});

function GetJWT() {
    return localStorage.getItem('jwt');
}
