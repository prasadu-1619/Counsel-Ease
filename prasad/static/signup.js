// JavaScript for hiding/unhiding password
function togglePasswordVisibility() {
  var passwordInput = document.getElementById("password");
  if (passwordInput.type === "password") {
    passwordInput.type = "text";
  } else {
    passwordInput.type = "password";
  }
}

// Add event listener for password visibility toggle
document.querySelector(".eye").addEventListener("click", function(event) {
  event.preventDefault();
  togglePasswordVisibility();
});
