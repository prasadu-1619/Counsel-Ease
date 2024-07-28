document.addEventListener('DOMContentLoaded', function() {
    const eye = document.querySelector('.eye');
    const passwordInput = document.querySelector('#password');
  
    eye.addEventListener('click', function() {
      const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
      passwordInput.setAttribute('type', type);
      this.classList.toggle('active');
    });
  });
  