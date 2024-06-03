window.addEventListener('DOMContentLoaded', function(){
    fetch('http://127.0.0.1:5000/products')
    .then(response => response.json())
    .then(data => {
        console.log('Data received from API:', data); // Log the data received from the API
        let tableBody = document.getElementById('productsTableBody');
        tableBody.innerHTML = '';
        data.forEach(product => {
            let row = document.createElement('tr');
            row.innerHTML = `
                <td>${product.scan_id}</td>
                <td>${product.EAN_13}</td>
                <td>${product.Product_Name}</td> <!-- Include Product_Name if you want to display it -->
                <td>${product.Status}</td>
                <td>${product.timestamp}</td>
                <td>${product.scan_count}</td>
            `;
            tableBody.appendChild(row);
        });
    })
    .catch(error => {
        console.error('Error:', error);
    });
});
