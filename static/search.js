document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('search').addEventListener('click', function(){
        var searchForm = document.getElementById('search_form');
        if(searchForm.style.display === 'none') {
            searchForm.style.display = 'block';
        } else {
            searchForm.style.display = 'none';
        }
    });
    document.getElementById('search_form').addEventListener('submit', function(event) {
        event.preventDefault();
        var searchInput = document.getElementById('search_in').value.trim();
        if (!searchInput) {
            alert('Please provide input');
            return;
        }
        fetch('http://127.0.0.1:5000/search', {
            method: 'POST',
            body: new FormData(this)
        })
        .then(response => response.text())
        .then(data => {
            if (data.includes("No Results Found")) {
                alert("No Results Found");
            } else{

            window.location.href ='search.html?q=' + encodeURIComponent(searchInput) + '&results=' + encodeURIComponent(data);
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
    });
});
document.getElementById('camera').addEventListener('click', executeCameraScript);
function executeCameraScript() {
    fetch('http://127.0.0.1:5000/execute_camera_script', {
        method: 'POST',
    })
    .then(response=>{
        if(response.ok) {
            console.log("Executed Successfully");
        }
        else{
            console.error('Error Executing ');
        }
    })
    .catch(error=> {
        console.error('Error:', error);
    });
}