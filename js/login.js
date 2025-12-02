// Employee Management System - Login JavaScript
class LoginSystem {
    constructor() {
        this.loginAttempts = 0;
        this.maxAttempts = window.employeeData?.validation?.max_login_attempts || 3;
        this.validationRules = window.employeeData?.validation || {
            username_min_length: 3,
            password_min_length: 6,
            max_login_attempts: 3
        };
        this.employees = window.employeeData?.employees || [];
        
        this.init();
    }

    init() {
        this.bindEvents();
        this.generateCSRFToken();
        this.checkLoginAttempts();
    }

    bindEvents() {
        // Form submission
        //const form = document.getElementById('loginForm');
       //form.addEventListener('submit', (e) => this.handleFormSubmit(e));

        // Password toggle
        const passwordToggle = document.getElementById('passwordToggle');
        passwordToggle.addEventListener('click', () => this.togglePassword());

        // Real-time validation
        const usernameInput = document.getElementById('username');
        const passwordInput = document.getElementById('password');

        usernameInput.addEventListener('blur', () => this.validateUsername());
        usernameInput.addEventListener('input', () => this.clearError('username'));
        
        passwordInput.addEventListener('blur', () => this.validatePassword());
        passwordInput.addEventListener('input', () => this.clearError('password'));

        // Forgot password link
        const forgotPassword = document.querySelector('.forgot-password');
        forgotPassword.addEventListener('click', (e) => this.handleForgotPassword(e));

        // Demo account quick login
        this.addDemoAccountListeners();
    }

    generateCSRFToken() {
        const token = 'csrf_' + Math.random().toString(36).substr(2, 9) + Date.now().toString(36);
        document.getElementById('csrf_token').value = token;
        sessionStorage.setItem('csrf_token', token);
    }

    checkLoginAttempts() {
        const attempts = localStorage.getItem('login_attempts');
        if (attempts) {
            this.loginAttempts = parseInt(attempts);
            if (this.loginAttempts >= this.maxAttempts) {
                this.lockAccount();
            }
        }
    }

    validateUsername() {
        const username = document.getElementById('username').value.trim();
        const errorElement = document.getElementById('username-error');
        const inputElement = document.getElementById('username');

        if (!username) {
            this.showFieldError('username', 'Username or email is required');
            return false;
        }

        if (username.length < this.validationRules.username_min_length) {
            this.showFieldError('username', `Username must be at least ${this.validationRules.username_min_length} characters`);
            return false;
        }

        // Basic email validation if input contains @
        if (username.includes('@') && !this.isValidEmail(username)) {
            this.showFieldError('username', 'Please enter a valid email address');
            return false;
        }

        this.clearFieldError('username');
        return true;
    }

    validatePassword() {
        const password = document.getElementById('password').value;
        const errorElement = document.getElementById('password-error');

        if (!password) {
            this.showFieldError('password', 'Password is required');
            return false;
        }

        if (password.length < this.validationRules.password_min_length) {
            this.showFieldError('password', `Password must be at least ${this.validationRules.password_min_length} characters`);
            return false;
        }

        this.clearFieldError('password');
        return true;
    }

    isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    showFieldError(fieldName, message) {
        const errorElement = document.getElementById(`${fieldName}-error`);
        const inputElement = document.getElementById(fieldName);
        
        errorElement.textContent = message;
        errorElement.classList.add('show');
        inputElement.classList.add('error');
        inputElement.classList.remove('success');
    }

    clearFieldError(fieldName) {
        const errorElement = document.getElementById(`${fieldName}-error`);
        const inputElement = document.getElementById(fieldName);
        
        errorElement.textContent = '';
        errorElement.classList.remove('show');
        inputElement.classList.remove('error');
        inputElement.classList.add('success');
    }

    clearError(fieldName) {
        const errorElement = document.getElementById(`${fieldName}-error`);
        const inputElement = document.getElementById(fieldName);
        
        if (errorElement.textContent) {
            errorElement.textContent = '';
            errorElement.classList.remove('show');
            inputElement.classList.remove('error');
        }
    }

    togglePassword() {
        const passwordInput = document.getElementById('password');
        const eyeIcon = document.querySelector('.eye-icon');
        const eyeOffIcon = document.querySelector('.eye-off-icon');

        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            eyeIcon.classList.add('hidden');
            eyeOffIcon.classList.remove('hidden');
        } else {
            passwordInput.type = 'password';
            eyeIcon.classList.remove('hidden');
            eyeOffIcon.classList.add('hidden');
        }
    }

    // async handleFormSubmit(e) {
    //     e.preventDefault();

    //     // Check if account is locked
    //     if (this.loginAttempts >= this.maxAttempts) {
    //         this.showMessage('Account temporarily locked due to too many failed attempts. Please try again later.', 'error');
    //         return;
    //     }

    //     // Validate all fields
    //     const isUsernameValid = this.validateUsername();
    //     const isPasswordValid = this.validatePassword();

    //     if (!isUsernameValid || !isPasswordValid) {
    //         return;
    //     }

    //     // Show loading state
    //     this.showLoadingState(true);

    //     // Simulate network delay
    //     setTimeout(() => {
    //         this.processLogin();
    //     }, 1500);
    // }

    processLogin() {
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;
        const remember = document.getElementById('remember').checked;

        // Find matching employee
        const employee = this.employees.find(emp => 
            (emp.username === username || emp.email === username) && emp.password === password
        );

        if (employee) {
            // Successful login
            this.loginAttempts = 0;
            localStorage.removeItem('login_attempts');
            
            this.showMessage(`Welcome back, ${employee.username}! Redirecting to dashboard...`, 'success');
            
            // Simulate session creation
            const sessionData = {
                user_id: employee.id,
                username: employee.username,
                email: employee.email,
                role: employee.role,
                department: employee.department,
                login_time: new Date().toISOString(),
                remember_me: remember
            };

            if (remember) {
                localStorage.setItem('user_session', JSON.stringify(sessionData));
            } else {
                sessionStorage.setItem('user_session', JSON.stringify(sessionData));
            }

            // Redirect after success message
            setTimeout(() => {
                if (employee.role === 'Administrator')
                window.location.href = 'admin/admin.php';
            else 
                window.location.href = 'employee/employee.php';

                // this.resetForm();
            }, 2000);

        } else {
            // Failed login
            this.loginAttempts++;
            localStorage.setItem('login_attempts', this.loginAttempts.toString());

            const remainingAttempts = this.maxAttempts - this.loginAttempts;
            
            if (remainingAttempts > 0) {
                this.showMessage(`Invalid credentials. ${remainingAttempts} attempt(s) remaining.`, 'error');
            } else {
                this.lockAccount();
            }
        }

        this.showLoadingState(false);
    }

    lockAccount() {
        this.showMessage('Account temporarily locked due to too many failed attempts. Please contact support.', 'error');
        document.getElementById('loginBtn').disabled = true;
        
        // Auto-unlock after 5 minutes (for demo purposes)
        setTimeout(() => {
            this.unlockAccount();
        }, 300000); // 5 minutes
    }

    unlockAccount() {
        this.loginAttempts = 0;
        localStorage.removeItem('login_attempts');
        document.getElementById('loginBtn').disabled = false;
        this.showMessage('Account has been unlocked. You may try logging in again.', 'success');
    }

    showLoadingState(isLoading) {
        const loginBtn = document.getElementById('loginBtn');
        const btnText = loginBtn.querySelector('.btn-text');
        const spinner = loginBtn.querySelector('.loading-spinner');

        if (isLoading) {
            loginBtn.classList.add('loading');
            spinner.classList.remove('hidden');
            loginBtn.disabled = true;
        } else {
            loginBtn.classList.remove('loading');
            spinner.classList.add('hidden');
            loginBtn.disabled = false;
        }
    }

    showMessage(text, type) {
        const messageContainer = document.getElementById('message-container');
        const messageElement = document.getElementById('message');

        messageElement.textContent = text;
        messageElement.className = `message message--${type}`;
        messageContainer.classList.remove('hidden');

        // Auto-hide success messages after 5 seconds
        if (type === 'success') {
            setTimeout(() => {
                messageContainer.classList.add('hidden');
            }, 5000);
        }

        // Scroll to top to ensure message is visible
        messageContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    resetForm() {
        document.getElementById('loginForm').reset();
        this.clearFieldError('username');
        this.clearFieldError('password');
        
        // Reset password visibility
        const passwordInput = document.getElementById('password');
        const eyeIcon = document.querySelector('.eye-icon');
        const eyeOffIcon = document.querySelector('.eye-off-icon');
        
        passwordInput.type = 'password';
        eyeIcon.classList.remove('hidden');
        eyeOffIcon.classList.add('hidden');
    }

    handleForgotPassword(e) {
        e.preventDefault();
        window.location.href = 'forgot.php';
    }

    addDemoAccountListeners() {
        const demoAccounts = document.querySelectorAll('.demo-account');
        
        demoAccounts.forEach(account => {
            account.addEventListener('click', () => {
                const text = account.textContent;
                const match = text.match(/(\w+(?:\.\w+)?)\s*\/\s*(\w+)/);
                
                if (match) {
                    const [, username, password] = match;
                    document.getElementById('username').value = username;
                    document.getElementById('password').value = password;
                    
                    // Clear any existing errors
                    this.clearError('username');
                    this.clearError('password');
                    
                    // Add visual feedback
                    account.style.background = 'var(--color-primary)';
                    account.style.color = 'var(--color-btn-primary-text)';
                    
                    setTimeout(() => {
                        account.style.background = '';
                        account.style.color = '';
                    }, 1000);
                }
            });

            account.style.cursor = 'pointer';
            account.title = 'Click to use these credentials';
        });
    }
}

// Security Functions
class SecurityManager {
    static sanitizeInput(input) {
        if (typeof input !== 'string') return input;
        
        return input
            .replace(/[<>]/g, '') // Remove potential HTML tags
            .trim()
            .substring(0, 255); // Limit length
    }

    static validateCSRFToken() {
        const formToken = document.getElementById('csrf_token').value;
        const sessionToken = sessionStorage.getItem('csrf_token');
        
        return formToken === sessionToken && formToken !== '';
    }

    static logSecurityEvent(event, details) {
        const timestamp = new Date().toISOString();
        const logEntry = {
            timestamp,
            event,
            details,
            userAgent: navigator.userAgent,
            ip: 'client-side' // In real app, this would be server-side
        };
        
        console.log('Security Event:', logEntry);
        
        // In a real application, this would be sent to a security logging service
    }
}

// Session Management
class SessionManager {
    static checkExistingSession() {
        const session = localStorage.getItem('user_session') || sessionStorage.getItem('user_session');
        
        if (session) {
            try {
                const sessionData = JSON.parse(session);
                const loginTime = new Date(sessionData.login_time);
                const now = new Date();
                const sessionAge = (now - loginTime) / (1000 * 60 * 60); // Hours
                
                // Check if session is still valid (24 hours for remembered, 8 hours for session)
                const maxAge = sessionData.remember_me ? 24 : 8;
                
                if (sessionAge < maxAge) {
                    return sessionData;
                } else {
                    // Session expired
                    SessionManager.clearSession();
                }
            } catch (e) {
                // Invalid session data
                SessionManager.clearSession();
            }
        }
        
        return null;
    }

    static clearSession() {
        localStorage.removeItem('user_session');
        sessionStorage.removeItem('user_session');
        sessionStorage.removeItem('csrf_token');
    }
}

// Initialize the login system when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Check for existing session
    const existingSession = SessionManager.checkExistingSession();
    
    if (existingSession) {
        const messageContainer = document.getElementById('message-container');
        const messageElement = document.getElementById('message');
        
        messageElement.textContent = `You are already logged in as ${existingSession.username}. In a real application, you would be redirected to the dashboard.`;
        if (existingSession.username === 'Administrator')
            window.location.href = 'admin/admin.php';
        else
            window.location.href = 'employee/employee.php';
        messageElement.className = 'message message--success';
        messageContainer.classList.remove('hidden');
    }
    
    // Initialize login system
    const loginSystem = new LoginSystem();
    
    // Add global error handler
    window.addEventListener('error', (e) => {
        SecurityManager.logSecurityEvent('client_error', {
            message: e.message,
            filename: e.filename,
            lineno: e.lineno,
            colno: e.colno
        });
    });
});

// Export for potential testing
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { LoginSystem, SecurityManager, SessionManager };
}