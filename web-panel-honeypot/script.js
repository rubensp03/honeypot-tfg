document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('loginForm');
    const emailInput = document.getElementById('email');
    const passwordInput = document.getElementById('password');
    const togglePasswordBtn = document.querySelector('.toggle-password');
    const eyeOpenIcon = document.querySelector('.eye-open');
    const eyeClosedIcon = document.querySelector('.eye-closed');
    const submitBtn = document.querySelector('.submit-btn');
    const btnText = document.querySelector('.btn-text');
    const btnLoader = document.querySelector('.btn-loader');
    const forgotPasswordLink = document.querySelector('.forgot-password');

    // Toggle Password Visibility
    togglePasswordBtn.addEventListener('click', () => {
        const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        passwordInput.setAttribute('type', type);

        eyeOpenIcon.classList.toggle('hidden');
        eyeClosedIcon.classList.toggle('hidden');
    });

    // Form Submission
    loginForm.addEventListener('submit', (e) => {
        e.preventDefault();

        // Basic Client-side Validation
        if (!validateInput(emailInput) || !validateInput(passwordInput)) {
            return;
        }

        // Simulate Loading
        setLoading(true);

        // Honeypot Logic: Simulate check and fail constantly
        // Random delay between 800ms to 2400ms to mimic network variance
        const randomDelay = Math.floor(Math.random() * 1600) + 800;

        setTimeout(() => {
            setLoading(false);

            // Randomly pick an error message to display
            const errors = [
                'Invalid credentials provided.',
                'Account suspended. Contact support.',
                'Connection to authentication server timed out.',
                'Security token expired. Please refresh.'
            ];

            // 80% chance of "Invalid credentials", 20% others for variety
            const errorMsg = Math.random() > 0.2 ? errors[0] : errors[Math.floor(Math.random() * errors.length)];

            showToast(errorMsg, 'error');

            // Shake the form only on invalid credentials for visual feedback
            if (errorMsg === errors[0]) {
                loginForm.classList.add('shake');
                setTimeout(() => loginForm.classList.remove('shake'), 500);
            }

            // Clear password field to be annoying
            passwordInput.value = '';

            // Here you could send the collected data (email/password/ip) to a logging endpoint
            console.log(`[HONEYPOT] Capture attempt - User: ${emailInput.value} | Pass: ${passwordInput.value}`);

        }, randomDelay);
    });

    // Dummy Forgot Password Handler
    forgotPasswordLink.addEventListener('click', (e) => {
        e.preventDefault();
        showToast('Password reset link sent to registered email.', 'info');
    });

    // Input Validation Helper
    function validateInput(input) {
        if (!input.value.trim()) {
            input.parentElement.classList.add('shake');
            input.focus();
            setTimeout(() => input.parentElement.classList.remove('shake'), 500);
            showToast('This field is required.', 'error');
            return false;
        }
        return true;
    }

    // Loading State Helper
    function setLoading(isLoading) {
        if (isLoading) {
            submitBtn.disabled = true;
            btnText.classList.add('hidden');
            btnLoader.classList.remove('hidden');
            emailInput.disabled = true;
            passwordInput.disabled = true;
        } else {
            submitBtn.disabled = false;
            btnText.classList.remove('hidden');
            btnLoader.classList.add('hidden');
            emailInput.disabled = false;
            passwordInput.disabled = false;
            emailInput.focus(); // Refocus for next attempt
        }
    }

    // Toast Notification System
    function showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;

        let icon = '';
        if (type === 'error') {
            icon = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>';
        } else {
            icon = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>';
        }

        toast.innerHTML = `${icon}<span>${message}</span>`;
        container.appendChild(toast);

        // Remove after 3 seconds
        setTimeout(() => {
            toast.style.animation = 'slideIn 0.3s ease-out reverse';
            setTimeout(() => toast.remove(), 300); // Wait for animation
        }, 3000);
    }
});
