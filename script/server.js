const form = document.getElementById("expressionForm");
const results = document.getElementById("computing-resources");

form.addEventListener("submit", function(e) {
    e.preventDefault(); // Предотвращаем стандартное поведение браузера
    
    fetch('http://localhost:8080/ping', {
        method: 'GET'
    })
    .then((response) => response.json())
    .then((data) => {
        results.innerHTML += `<article class="result success">
        <span class="status-icon"></span>
        <span class="expression">
        computing server(localhost:8080)
        <br>
        last ping ${data.info}
        <br>
        the number of parallel calculations: -
        </span>
        </article>`
    })
    .catch((error) => {
        if (error.response | error.response.status !== 200) {
        alert(`Error: ${error}\n
        Вероятно, вы просто не запустили сервер`);
        console.error('Error:', error);
        }
    });
    
    return false;
});
