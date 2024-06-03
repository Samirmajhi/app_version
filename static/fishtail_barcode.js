document.addEventListener('DOMContentLoaded', function(){
    const successMessage = document.getElementById('successMessage');
    const errorMessage = document.getElementById('errorMessage');
    const addProduct = document.getElementById('addProduct');
    
    addProduct.addEventListener('click', function(event) {
        event.preventDefault();
        var ean = document.getElementById('ean').value;
        var name = document.getElementById('name').value;
        var status = document.getElementById('status').value;
        
        fetch('http://127.0.0.1:5000/add_product',{
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ EAN13: ean,Product_Name: name })
        })
        .then(response => response.json())
        .then(data => {
            if(data.success) {
                successMessage.textContent = 'Product added Successfully';
                successMessage.style.display = 'block';
                errorMessage.style.display = 'none';
                document.getElementById('ean').value = '';
                document.getElementById('name').value = '';
                document.getElementById('status').value = '';
            } else {
                errorMessage.textContent = data.error;
                errorMessage.style.display = 'block';
                successMessage.style.display = 'none';
            }
        })
        .catch(error => {
            console.error('Error Saving Data:', error);
            errorMessage.textContent = 'An error occurred while adding the product';
            errorMessage.style.display = 'block';
            successMessage.style.display = 'none';
        });
    });
});
