const form = document.getElementById("expressionForm");
const results = document.querySelector(".results");

form.addEventListener("submit", function(e) {
    e.preventDefault(); // Предотвращаем стандартное поведение браузера
    
    const jwt = GetJWT()
    if (jwt === '') {
        results.innerHTML = `<div class="result error">
        <span class="status-icon"></span>
        <span class="expression">Вы не авторизованы</span>
        </div>`
        return
    }

    fetch('http://localhost:8080/expressions', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
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
        } else if (response.status === 404) {
            results.innerHTML = `<div class="result error">
        <span class="status-icon"></span>
        <span class="expression">Выражения не были найдены :(</span>
        </div>`
        return
        } else if (response.status === 500) {
            results.innerHTML = `<div class="result error">
        <span class="status-icon"></span>
        <span class="expression">Ошибка сервера :(</span>
        </div>`
        alert(response.error);
        return
        } else {
            return response.json()
        }
    })
    .then((data) => {
        const dat = data.expressions
        for (i in dat) {
            results.innerHTML += `<div class="result success">
            <span class="status-icon"></span>
            <span class="expression">ID: ${dat[i].ID}<br>
            Expression: ${dat[i].Expression}<br>
            Login: ${dat[i].LoginUser}<br>
            Status: ${dat[i].Status}<br>
            CreatedAt: ${dat[i].CreatedAt}<br>
            UpdatedAt: ${dat[i].UpdatedAt}<br>
            Result: ${dat[i].Result}</span>
            </div>`;
        }
    })    
    .catch((error) => {
        alert(`Error: ${error}\nВероятно, сервер не доступен, либо вы не авторизованы`);
        console.error('Error:', error);
    });    
    
    return false;
});

function GetJWT() {
    return localStorage.getItem('jwt')
}
