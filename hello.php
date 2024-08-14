<?php
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "mohit"; // Specify your database name

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
echo "Connected successfully<br>";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Validate and sanitize input
    $user = filter_var($_POST['username'], FILTER_SANITIZE_STRING);
    $pass = $_POST['password']; // Assume password is plain text here
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);

    // Check for valid email
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        die("Invalid email format.");
    }

    // Hash the password
    $hashed_password = password_hash($pass, PASSWORD_DEFAULT);

    // Prepare and bind
    $stmt = $conn->prepare("INSERT INTO users (username, password, email) VALUES (?, ?, ?)");
    if ($stmt === false) {
        die("Prepare failed: " . $conn->error);
    }
    
    $stmt->bind_param("sss", $user, $hashed_password, $email);

    // Execute the statement
    if ($stmt->execute()) {
        echo "New record created successfully";
    } else {
        echo "Error: " . $stmt->error;
    }

    $stmt->close();
}

$conn->close();
?>
