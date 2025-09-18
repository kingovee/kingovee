document.addEventListener("DOMContentLoaded", async () => {
  let res = await fetch("/api/questions");
  let questions = await res.json();
  let container = document.getElementById("quiz-container");

  questions.forEach(q => {
    let div = document.createElement("div");
    div.className = "mb-4 border p-3 rounded";
    div.innerHTML = `<p class="font-semibold">${q.question_text}</p>`;

    if(q.type === "mcq" && q.options){
      for (let [key, val] of Object.entries(q.options)){
        div.innerHTML += `<label class="block"><input type="radio" name="q${q.id}" value="${key}"> ${key}. ${val}</label>`;
      }
    } else {
      div.innerHTML += `<textarea name="q${q.id}" class="border p-2 w-full mt-2"></textarea>`;
    }
    container.appendChild(div);
  });

  document.getElementById("submitBtn").addEventListener("click", async () => {
    let student = document.getElementById("studentName").value;
    if(!student){ alert("Enter your name"); return; }

    let answers = [];
    questions.forEach(q=>{
      let val = "";
      if(q.type==="mcq"){
        let chosen = document.querySelector(`input[name=q${q.id}]:checked`);
        if(chosen) val = chosen.value;
      } else {
        val = document.querySelector(`textarea[name=q${q.id}]`).value;
      }
      answers.push({id:q.id, answer:val, score:0});
    });

    await fetch("/api/submit", {
      method:"POST", headers:{"Content-Type":"application/json"},
      body:JSON.stringify({student, answers})
    });
    alert("Quiz submitted!");
  });
});
