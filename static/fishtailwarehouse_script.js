
const sideMenu=document.querySelector('aside');
const Menubtn=document.querySelector('#menu_bar');
const closebtn=document.querySelector('#close_btn');
Menubtn.addEventListener('click',()=>{
sideMenu.style.display = "block"
});
closebtn.addEventListener('click',()=>{
    sideMenu.style.display = "none"
});
document.getElementById('logout').addEventListener('click',function(){
    window.location.href = 'fishtail2.html';
    document.getElementById('email').value ='email';
});
