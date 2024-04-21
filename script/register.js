const form = document.querySelector("form");
const input_login = document.getElementById("login");
const input_password = document.getElementById("password")
const results = document.querySelector(".form__message");

form.addEventListener("submit", function(e) {
    e.preventDefault(); // Предотвращаем стандартное действие браузера

    const login = input_login.value;
    const password = input_password.value;

    if (login === '' || password === '') {
        results.innerHTML = `<p class="form__message">Поля логина и пароля должны быть заполнены</p>`;
        return
    }
    
    fetch('http://localhost:8080/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
            login: login,
            password: password
        }),
    })
    .then((response) => response.json())
    .then((data) => {
        console.log('result:', data.message);
        results.innerHTML = `<p class="form__message">${data.message}</p>`;
    })
    .catch((error) => {
        alert(`Error: ${error}\n
        Скорее всего вы просто не запустили сервер`);
        console.error('Error:', error);
    });

    // Очистка поля ввода после отправки
    input_login.value = '';
    input_password.value = '';
});
