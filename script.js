// Simulación de usuarios registrados
let users = JSON.parse(localStorage.getItem('users')) || [
    { username: 'admin', password: 'admin123', role: 'admin' }
];

// Función de registro
function register() {
    const newUsername = document.getElementById('newUsername').value;
    const newPassword = document.getElementById('newPassword').value;
    const registerMessage = document.getElementById('registerMessage');

    if (users.find(user => user.username === newUsername)) {
        registerMessage.textContent = 'El nombre de usuario ya está en uso.';
        registerMessage.style.color = 'red';
        return;
    }

    users.push({ username: newUsername, password: newPassword, role: 'user' });
    localStorage.setItem('users', JSON.stringify(users));

    registerMessage.textContent = 'Usuario registrado con éxito. Ahora puede iniciar sesión.';
    registerMessage.style.color = 'green';
}

// Función de inicio de sesión
function login() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const loginMessage = document.getElementById('loginMessage');

    const user = users.find(user => user.username === username && user.password === password);

    if (user) {
        const sessionToken = Math.random().toString(36).substr(2);
        sessionStorage.setItem('sessionToken', sessionToken);
        sessionStorage.setItem('loggedInUser', JSON.stringify({ username: user.username, role: user.role }));
        window.location.href = 'dashboard.html';
    } else {
        loginMessage.textContent = 'Usuario o contraseña incorrectos.';
        loginMessage.style.color = 'red';
    }
}

// Verificación de sesión
function checkLogin() {
    const sessionToken = sessionStorage.getItem('sessionToken');
    const loggedInUser = JSON.parse(sessionStorage.getItem('loggedInUser'));

    if (!sessionToken || !loggedInUser) {
        window.location.href = 'login.html';
    }
}

// Cerrar sesión
function logout() {
    sessionStorage.clear();
    window.location.href = 'login.html';
}

// Envío del formulario de consentimiento
function submitForm() {
    const photoConsent = document.getElementById("photoConsent").checked;
    const biometricConsent = document.getElementById("biometricConsent").checked;
    const dataConsent = document.getElementById("dataConsent").checked;

    let photoStats = parseInt(localStorage.getItem('photoStats')) || 0;
    let biometricStats = parseInt(localStorage.getItem('biometricStats')) || 0;
    let dataStats = parseInt(localStorage.getItem('dataStats')) || 0;

    let resultMessage = "Usted ha autorizado el uso de los siguientes datos: ";

    if (photoConsent || biometricConsent || dataConsent) {
        if (photoConsent) {
            resultMessage += "Fotografías, ";
            photoStats++;
            localStorage.setItem('photoStats', photoStats);
        }
        if (biometricConsent) {
            resultMessage += "Datos biométricos, ";
            biometricStats++;
            localStorage.setItem('biometricStats', biometricStats);
        }
        if (dataConsent) {
            resultMessage += "Datos personales, ";
            dataStats++;
            localStorage.setItem('dataStats', dataStats);
        }
        resultMessage = resultMessage.slice(0, -2) + ".";
    } else {
        resultMessage = "No ha autorizado el uso de ningún dato.";
    }

    document.getElementById("resultMessage").textContent = resultMessage;
    updateStats();
}

// Actualización de estadísticas en el panel de administración
function updateStats() {
    document.getElementById('photoStats').textContent = localStorage.getItem('photoStats') || 0;
    document.getElementById('biometricStats').textContent = localStorage.getItem('biometricStats') || 0;
    document.getElementById('dataStats').textContent = localStorage.getItem('dataStats') || 0;
}

// Borrar datos almacenados en Local Storage
function clearData() {
    localStorage.clear();
    updateStats();
}

// Ejecutar al cargar el dashboard
if (window.location.pathname.includes('dashboard.html')) {
    checkLogin();
    updateStats();
}
// Función para manejar el envío del consentimiento
function submitConsent() {
    const photoConsent = document.getElementById('photoConsent').checked;
    const biometricConsent = document.getElementById('biometricConsent').checked;
    const dataConsent = document.getElementById('dataConsent').checked;

    let resultMessage = "Consentimiento recibido para: ";

    if (photoConsent || biometricConsent || dataConsent) {
        if (photoConsent) {
            resultMessage += "Fotografías, ";
            let photoStats = parseInt(localStorage.getItem('photoStats') || 0);
            localStorage.setItem('photoStats', ++photoStats);
        }
        if (biometricConsent) {
            resultMessage += "Datos biométricos, ";
            let biometricStats = parseInt(localStorage.getItem('biometricStats') || 0);
            localStorage.setItem('biometricStats', ++biometricStats);
        }
        if (dataConsent) {
            resultMessage += "Datos personales, ";
            let dataStats = parseInt(localStorage.getItem('dataStats') || 0);
            localStorage.setItem('dataStats', ++dataStats);
        }
        resultMessage = resultMessage.slice(0, -2) + ".";
    } else {
        resultMessage = "No ha autorizado el uso de ningún dato.";
    }

    document.getElementById("resultMessage").textContent = resultMessage;
    updateStats();
}

// Actualización de estadísticas en el panel de administración
function updateStats() {
    document.getElementById('photoStats').textContent = localStorage.getItem('photoStats') || 0;
    document.getElementById('biometricStats').textContent = localStorage.getItem('biometricStats') || 0;
    document.getElementById('dataStats').textContent = localStorage.getItem('dataStats') || 0;
}

// Borrar datos almacenados en Local Storage
function clearData() {
    localStorage.clear();
    updateStats();
}

// Cierre de sesión
function logout() {
    sessionStorage.removeItem('sessionToken');
    window.location.href = 'index.html';
}

// Ejecutar al cargar el dashboard
if (window.location.pathname.includes('dashboard.html')) {
    checkLogin();
    updateStats();
}
