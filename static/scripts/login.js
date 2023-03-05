const togglePassword = document.querySelector("#togglePassword");
const password = document.querySelector("#password");

togglePassword.addEventListener("click", function () {
  /* toggle the type attribute */
  const type =
    password.getAttribute("type") === "password" ? "text" : "password";
  password.setAttribute("type", type);

  /* toggle the icon */
  this.classList.toggle("bi-eye");
});

$(document).ready(function () {
    $('#signup-form').submit(function (e) {
        e.preventDefault();
        $.ajax({
            url: '/signup',
            method: 'POST',
            data: $(this).serialize(),
            dataType: 'json',
            success: function (response) {
                if (response.error) {
                    alert(response.error);
                } else (response.success) {
                    alert(response.success);
                    window.location.href = '/login';
                }
            }
        });
    });
});
