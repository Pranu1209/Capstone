// Add event listener for hero section text animation (optional)

const heroText = document.querySelector('.hero p');

if (heroText) {
  const text = heroText.textContent;
  let index = 0;
  let speed = 50; // Adjust speed as desired

  function typeWriter() {
    if (index < text.length) {
      heroText.textContent = text.substring(0, index + 1);
      index++;
      setTimeout(typeWriter, speed);
    } else {
      // Optionally add a delay before restarting the animation
      setTimeout(() => {
        index = 0;
        typeWriter();
      }, 2000); // Adjust delay as desired
    }
  }

  typeWriter();
}

function validateForm() {
    var username = document.getElementById('username').value;
    var password = document.getElementById('password').value;
    var usernameError = document.getElementById('username-error');
    var passwordError = document.getElementById('password-error');
    var alreadyRegistered = document.getElementById('already-registered');

    // Validate username
    if (username.length < 6 || !(/[A-Za-z]/.test(username)) || !(/\d/.test(username)) || !(/[@#$%^&+=]/.test(username))) {
        usernameError.innerHTML = 'Username must be at least 6 characters long and contain at least one character, one number, and one special character.';
        return false;
    } else {
        usernameError.innerHTML = '';
    }

    // Validate password
    if (password.length < 8 || !(/[A-Za-z]/.test(password)) || !(/\d/.test(password)) || !(/[@#$%^&+=]/.test(password))) {
        passwordError.innerHTML = 'Password must be at least 8 characters long and contain at least one character, one number, and one special character.';
        return false;
    } else {
        passwordError.innerHTML = '';
    }

    // Check if username is already registered
    if (alreadyRegistered.innerHTML.trim() !== '') {
      return false; // Prevent form submission if already registered
  }


    return true;
}
  

document.addEventListener('DOMContentLoaded', function() {
  const form = document.getElementById('submitTaskForm');

  form.addEventListener('submit', function(event) {
      // Perform form validation
      const taskName = document.getElementById('taskName').value;
      const complexity = document.getElementById('complexity').value;
      const size = document.getElementById('size').value;
      const taskType = document.getElementById('taskType').value;

      if (!taskName || !complexity || !size || !taskType) {
          event.preventDefault();
          alert('Please fill in all required fields.');
          return;
      }

      // Additional custom validations can be added here

      // If everything is valid, allow the form to be submitted
  });
});
