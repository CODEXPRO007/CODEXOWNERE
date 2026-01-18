<?php
require_once 'config.php';
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('Access-Control-Allow-Credentials: true');

session_start();

function connectDB() {
    global $config;
    $conn = new mysqli($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name']);
    if($conn->connect_error) {
        error_log("Database connection failed: " . $conn->connect_error);
        return null;
    }
    return $conn;
}

$action = $_GET['action'] ?? '';
$input = json_decode(file_get_contents('php://input'), true);
if(empty($input)) $input = $_POST;

switch($action) {
    case 'verify':
        $license = $input['license'] ?? '';
        $device = $input['device'] ?? '';
        $game = $input['game'] ?? '';
        
        if(empty($license) || empty($device) || $game != $config['game_name']) {
            echo json_encode(['status' => false, 'reason' => 'Invalid request']);
            break;
        }
        
        $conn = connectDB();
        if(!$conn) {
            echo json_encode(['status' => false, 'reason' => 'Database error']);
            break;
        }
        
        $stmt = $conn->prepare("SELECT k.*, u.username, u.credits FROM keys_table k JOIN users u ON k.created_by = u.id WHERE k.license_key = ? AND k.is_active = 1");
        $stmt->bind_param("s", $license);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if($result->num_rows === 0) {
            echo json_encode(['status' => false, 'reason' => 'Invalid license key']);
            $conn->close();
            break;
        }
        
        $key_data = $result->fetch_assoc();
        
        $stmt = $conn->prepare("SELECT COUNT(*) as used FROM key_usage WHERE license_key = ?");
        $stmt->bind_param("s", $license);
        $stmt->execute();
        $usage = $stmt->get_result()->fetch_assoc();
        
        if($usage['used'] >= $key_data['max_devices']) {
            echo json_encode(['status' => false, 'reason' => 'Device limit reached']);
            $conn->close();
            break;
        }
        
        $stmt = $conn->prepare("SELECT id FROM key_usage WHERE license_key = ? AND device_id = ?");
        $stmt->bind_param("ss", $license, $device);
        $stmt->execute();
        
        if($stmt->get_result()->num_rows === 0) {
            $stmt = $conn->prepare("INSERT INTO key_usage (license_key, device_id) VALUES (?, ?)");
            $stmt->bind_param("ss", $license, $device);
            $stmt->execute();
        }
        
        $expired = false;
        if($key_data['expires_at']) {
            $expires = strtotime($key_data['expires_at']);
            if(time() > $expires) {
                $expired = true;
                $stmt = $conn->prepare("UPDATE keys_table SET is_active = 0 WHERE id = ?");
                $stmt->bind_param("i", $key_data['id']);
                $stmt->execute();
            }
        }
        
        if($expired) {
            echo json_encode(['status' => false, 'reason' => 'License expired']);
            $conn->close();
            break;
        }
        
        $days_left = 0;
        if($key_data['expires_at']) {
            $days_left = ceil((strtotime($key_data['expires_at']) - time()) / 86400);
            if($days_left < 0) $days_left = 0;
        }
        
        $token = bin2hex(random_bytes(16));
        $expiry_text = $days_left > 0 ? "Expires in {$days_left} days" : "Lifetime";
        
        echo json_encode([
            'status' => true,
            'data' => [
                'token' => $token,
                'credit' => 'Balance: $' . number_format($key_data['credits'], 2),
                'expiry' => $expiry_text,
                'modname' => 'LUNAR CLIENT VIP',
                'device_count' => $usage['used'] + 1,
                'max_devices' => $key_data['max_devices'],
                'created_by' => $key_data['username']
            ]
        ]);
        
        $conn->close();
        break;
        
    case 'generate_key':
        if(!isset($_SESSION['user_id'])) {
            echo json_encode(['status' => false, 'reason' => 'Not authenticated']);
            break;
        }
        
        $days = $input['days'] ?? 30;
        $devices = $input['devices'] ?? 1;
        $user_id = $_SESSION['user_id'];
        
        if($days < 1 || $devices < 1) {
            echo json_encode(['status' => false, 'reason' => 'Invalid values']);
            break;
        }
        
        $conn = connectDB();
        if(!$conn) {
            echo json_encode(['status' => false, 'reason' => 'Database error']);
            break;
        }
        
        $stmt = $conn->prepare("SELECT credits, role FROM users WHERE id = ?");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();
        
        if(!$user) {
            echo json_encode(['status' => false, 'reason' => 'User not found']);
            $conn->close();
            break;
        }
        
        $cost = ($days * 0.5) + ($devices * 0.5);
        
        if($user['role'] != 'admin' && $user['credits'] < $cost) {
            echo json_encode(['status' => false, 'reason' => 'Insufficient credits']);
            $conn->close();
            break;
        }
        
        if($user['role'] != 'admin') {
            $new_credits = $user['credits'] - $cost;
            $stmt = $conn->prepare("UPDATE users SET credits = ? WHERE id = ?");
            $stmt->bind_param("di", $new_credits, $user_id);
            $stmt->execute();
        }
        
        $random_number = str_pad(mt_rand(0, 9999), 4, '0', STR_PAD_LEFT);
        $license_key = 'LUNAR-' . $random_number;
        
        if($days == 99999999999999999) {
            $expires_at = NULL;
        } else {
            $expires_at = date('Y-m-d H:i:s', strtotime("+{$days} days"));
        }
        
        $stmt = $conn->prepare("INSERT INTO keys_table (license_key, days, device_limit, created_by, max_devices, expires_at) VALUES (?, ?, ?, ?, ?, ?)");
        $stmt->bind_param("siiiis", $license_key, $days, $devices, $user_id, $devices, $expires_at);
        
        if($stmt->execute()) {
            echo json_encode([
                'status' => true,
                'key' => $license_key,
                'days' => $days,
                'devices' => $devices,
                'cost' => $cost,
                'expires' => $expires_at
            ]);
        } else {
            echo json_encode(['status' => false, 'reason' => 'Failed to generate key: ' . $conn->error]);
        }
        
        $conn->close();
        break;
        
    case 'login':
        $username = $input['username'] ?? '';
        $password = $input['password'] ?? '';
        
        if(empty($username) || empty($password)) {
            echo json_encode(['status' => false, 'reason' => 'Missing credentials']);
            break;
        }
        
        $conn = connectDB();
        if(!$conn) {
            echo json_encode(['status' => false, 'reason' => 'Database error']);
            break;
        }
        
        $stmt = $conn->prepare("SELECT id, username, password_hash, role, credits FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if($result->num_rows === 0) {
            echo json_encode(['status' => false, 'reason' => 'Invalid username or password']);
            $conn->close();
            break;
        }
        
        $user = $result->fetch_assoc();
        
        if(password_verify($password, $user['password_hash'])) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['role'] = $user['role'];
            $_SESSION['credits'] = $user['credits'];
            
            echo json_encode([
                'status' => true,
                'user' => [
                    'id' => $user['id'],
                    'username' => $user['username'],
                    'role' => $user['role'],
                    'credits' => $user['credits']
                ]
            ]);
        } else {
            echo json_encode(['status' => false, 'reason' => 'Invalid username or password']);
        }
        
        $conn->close();
        break;
        
    case 'register':
        $username = $input['username'] ?? '';
        $password = $input['password'] ?? '';
        $refer_code = $input['refer_code'] ?? '';
        
        if(empty($username) || empty($password) || empty($refer_code)) {
            echo json_encode(['status' => false, 'reason' => 'All fields required']);
            break;
        }
        
        $conn = connectDB();
        if(!$conn) {
            echo json_encode(['status' => false, 'reason' => 'Database error']);
            break;
        }
        
        $stmt = $conn->prepare("SELECT id, bonus_credits FROM referrals WHERE refer_code = ? AND is_active = 1");
        $stmt->bind_param("s", $refer_code);
        $stmt->execute();
        $referral = $stmt->get_result()->fetch_assoc();
        
        if(!$referral) {
            echo json_encode(['status' => false, 'reason' => 'Invalid referral code']);
            $conn->close();
            break;
        }
        
        $stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        
        if($stmt->get_result()->num_rows > 0) {
            echo json_encode(['status' => false, 'reason' => 'Username already exists']);
            $conn->close();
            break;
        }
        
        $password_hash = password_hash($password, PASSWORD_DEFAULT);
        $user_refer_code = 'USER-' . strtoupper(bin2hex(random_bytes(5)));
        $bonus = $referral['bonus_credits'];
        
        $stmt = $conn->prepare("INSERT INTO users (username, password_hash, refer_code, referred_by, credits) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("sssid", $username, $password_hash, $user_refer_code, $referral['id'], $bonus);
        
        if($stmt->execute()) {
            $stmt = $conn->prepare("UPDATE referrals SET used_times = used_times + 1 WHERE id = ?");
            $stmt->bind_param("i", $referral['id']);
            $stmt->execute();
            
            $user_id = $conn->insert_id;
            $_SESSION['user_id'] = $user_id;
            $_SESSION['username'] = $username;
            $_SESSION['role'] = 'user';
            $_SESSION['credits'] = $bonus;
            
            echo json_encode([
                'status' => true,
                'user' => [
                    'id' => $user_id,
                    'username' => $username,
                    'role' => 'user',
                    'credits' => $bonus
                ],
                'bonus' => $bonus
            ]);
        } else {
            echo json_encode(['status' => false, 'reason' => 'Registration failed: ' . $conn->error]);
        }
        
        $conn->close();
        break;
        
    case 'get_keys':
        if(!isset($_SESSION['user_id'])) {
            echo json_encode(['status' => false, 'reason' => 'Not authenticated']);
            break;
        }
        
        $conn = connectDB();
        if(!$conn) {
            echo json_encode(['status' => false, 'reason' => 'Database error']);
            break;
        }
        
        $user_id = $_SESSION['user_id'];
        $stmt = $conn->prepare("SELECT license_key, days, device_limit, created_at, expires_at, is_active FROM keys_table WHERE created_by = ? ORDER BY created_at DESC");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();
        
        $keys = [];
        while($row = $result->fetch_assoc()) {
            $keys[] = $row;
        }
        
        echo json_encode(['status' => true, 'keys' => $keys]);
        $conn->close();
        break;
        
    case 'get_stats':
        if(!isset($_SESSION['user_id'])) {
            echo json_encode(['status' => false, 'reason' => 'Not authenticated']);
            break;
        }
        
        $conn = connectDB();
        if(!$conn) {
            echo json_encode(['status' => false, 'reason' => 'Database error']);
            break;
        }
        
        $user_id = $_SESSION['user_id'];
        
        $stmt = $conn->prepare("SELECT username, role, credits FROM users WHERE id = ?");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();
        
        $stmt = $conn->prepare("SELECT COUNT(*) as total, SUM(days) as total_days, SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active FROM keys_table WHERE created_by = ?");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $stats = $stmt->get_result()->fetch_assoc();
        
        echo json_encode([
            'status' => true,
            'user' => $user,
            'stats' => $stats
        ]);
        
        $conn->close();
        break;
        
    case 'transfer_credits':
        if(!isset($_SESSION['user_id'])) {
            echo json_encode(['status' => false, 'reason' => 'Not authenticated']);
            break;
        }
        
        $to_user = $input['to_user'] ?? '';
        $amount = floatval($input['amount'] ?? 0);
        $from_id = $_SESSION['user_id'];
        
        if(empty($to_user) || $amount <= 0) {
            echo json_encode(['status' => false, 'reason' => 'Invalid transfer']);
            break;
        }
        
        $conn = connectDB();
        if(!$conn) {
            echo json_encode(['status' => false, 'reason' => 'Database error']);
            break;
        }
        
        $stmt = $conn->prepare("SELECT credits, role FROM users WHERE id = ?");
        $stmt->bind_param("i", $from_id);
        $stmt->execute();
        $sender = $stmt->get_result()->fetch_assoc();
        
        if($sender['role'] != 'admin' && $sender['credits'] < $amount) {
            echo json_encode(['status' => false, 'reason' => 'Insufficient balance']);
            $conn->close();
            break;
        }
        
        $stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->bind_param("s", $to_user);
        $stmt->execute();
        $receiver = $stmt->get_result()->fetch_assoc();
        
        if(!$receiver) {
            echo json_encode(['status' => false, 'reason' => 'Recipient not found']);
            $conn->close();
            break;
        }
        
        if($sender['role'] != 'admin') {
            $stmt = $conn->prepare("UPDATE users SET credits = credits - ? WHERE id = ?");
            $stmt->bind_param("di", $amount, $from_id);
            $stmt->execute();
        }
        
        $stmt = $conn->prepare("UPDATE users SET credits = credits + ? WHERE id = ?");
        $stmt->bind_param("di", $amount, $receiver['id']);
        $stmt->execute();
        
        $stmt = $conn->prepare("INSERT INTO transactions (from_user, to_user, amount, type) VALUES (?, ?, ?, 'transfer')");
        $stmt->bind_param("iid", $from_id, $receiver['id'], $amount);
        $stmt->execute();
        
        echo json_encode(['status' => true, 'message' => "Transferred \${$amount} to {$to_user}"]);
        
        $conn->close();
        break;
        
    case 'create_referral':
        if(!isset($_SESSION['user_id'])) {
            echo json_encode(['status' => false, 'reason' => 'Not authenticated']);
            break;
        }
        
        $user_id = $_SESSION['user_id'];
        $bonus = floatval($input['bonus'] ?? 5.00);
        $max_uses = intval($input['max_uses'] ?? NULL);
        
        if($bonus <= 0) {
            echo json_encode(['status' => false, 'reason' => 'Invalid bonus amount']);
            break;
        }
        
        $conn = connectDB();
        if(!$conn) {
            echo json_encode(['status' => false, 'reason' => 'Database error']);
            break;
        }
        
        $refer_code = 'REF-' . strtoupper(bin2hex(random_bytes(4)));
        $stmt = $conn->prepare("INSERT INTO referrals (refer_code, created_by, bonus_credits, max_uses) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("sidi", $refer_code, $user_id, $bonus, $max_uses);
        
        if($stmt->execute()) {
            echo json_encode([
                'status' => true,
                'refer_code' => $refer_code,
                'bonus' => $bonus,
                'max_uses' => $max_uses
            ]);
        } else {
            echo json_encode(['status' => false, 'reason' => 'Failed to create referral: ' . $conn->error]);
        }
        
        $conn->close();
        break;
        
    case 'get_users':
        if(!isset($_SESSION['user_id'])) {
            echo json_encode(['status' => false, 'reason' => 'Not authenticated']);
            break;
        }
        
        $conn = connectDB();
        if(!$conn) {
            echo json_encode(['status' => false, 'reason' => 'Database error']);
            break;
        }
        
        $stmt = $conn->prepare("SELECT username, role, credits, created_at FROM users ORDER BY created_at DESC");
        $stmt->execute();
        $result = $stmt->get_result();
        
        $users = [];
        while($row = $result->fetch_assoc()) {
            $users[] = $row;
        }
        
        echo json_encode(['status' => true, 'users' => $users]);
        $conn->close();
        break;
        
    default:
        echo json_encode(['status' => false, 'reason' => 'Invalid action']);
}
?>