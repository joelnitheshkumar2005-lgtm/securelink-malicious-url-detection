// Main JavaScript file for SecureLink

document.addEventListener('DOMContentLoaded', () => {
    // Add hover effect to table rows if they exist
    const rows = document.querySelectorAll('tr');
    rows.forEach(row => {
        row.addEventListener('mouseenter', () => {
            row.style.transition = 'background 0.2s';
        });
    });

    // Theme Toggle Logic
    const themeToggle = document.getElementById('theme-toggle');
    const body = document.body;
    const icon = themeToggle?.querySelector('i');
    const text = themeToggle?.querySelector('span');

    // Check local storage
    if (localStorage.getItem('theme') === 'light') {
        enableLightMode();
    }

    if (themeToggle) {
        themeToggle.addEventListener('click', (e) => {
            e.preventDefault();
            if (body.classList.contains('light-mode')) {
                disableLightMode();
            } else {
                enableLightMode();
            }
        });
    }

    function enableLightMode() {
        body.classList.add('light-mode');
        localStorage.setItem('theme', 'light');
        if (icon) {
            icon.classList.remove('fa-moon');
            icon.classList.add('fa-sun');
        }
        if (text) text.textContent = 'Light Mode';
    }

    function disableLightMode() {
        body.classList.remove('light-mode');
        localStorage.setItem('theme', 'dark');
        if (icon) {
            icon.classList.remove('fa-sun');
            icon.classList.add('fa-moon');
        }
        if (text) text.textContent = 'Dark Mode';
    }

    console.log('SecureLink App Initialized');
});
