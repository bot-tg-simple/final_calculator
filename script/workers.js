const form = document.getElementById("expressionForm");
const results = document.querySelector(".results");

form.addEventListener("submit", function(e) {
    e.preventDefault(); // Предотвращаем стандартное поведение браузера
    
    fetch('http://localhost:8080/workers', {
        method: 'GET'
    })
    .then((response) => response.json())
    .then((data) => {
        const info = data.expressions;
        if (info.length === 0) {
            results.innerHTML = `<article class="result pending">
        <span class="status-icon"></span>
        <span class="expression">
        Нет выполняющихся выражений
        </span>
        </article>`
        return
        } 
        results.innerHTML = ``
        for (i in info) {
            console.log(i)
        results.innerHTML += `<article class="result success">
        <span class="status-icon"></span>
        <span class="expression">
        id: ${i}
        <br>
        runtime: ${info[i]}
        </span>
        </article>`
        }
    })
    .catch((error) => {
        console.log(error);
        if (error.response | error.response.status !== 200) {
        alert(`Error: ${error}\n
        Вероятно, вы просто не запустили сервер`);
        console.error('Error:', error);
        }
    });
    
    return false;
});
