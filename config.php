<?php
$config = [
    'db_host' => 'Your',
    'db_name' => 'Your',
    'db_user' => 'Your',
    'db_pass' => 'Your',
    'game_name' => 'FREEFIRE' // Don't change it Otherwise the auth error bruh
];

session_set_cookie_params([
    'lifetime' => 86400,
    'path' => '/',
    'domain' => $_SERVER['HTTP_HOST'],
    'secure' => isset($_SERVER['HTTPS']),
    'httponly' => true,
    'samesite' => 'Lax'
]);

session_start();
?>