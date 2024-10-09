
const mobileButton = document.querySelector('.exp-sidebar-navigation-toggle');
const sidebar = document.querySelector('.exp-sidebar-navigation');

if (mobileButton && sidebar) {
    mobileButton.addEventListener('click', (ev) => {
        sidebar.classList.toggle('open');
        mobileButton.classList.toggle('open');
    });
}