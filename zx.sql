-- Create users table
CREATE TABLE IF NOT EXISTS `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `role` varchar(20) NOT NULL DEFAULT 'user',
  `credits` decimal(15,2) NOT NULL DEFAULT '0.00',
  `refer_code` varchar(20) DEFAULT NULL,
  `referred_by` int(11) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`),
  UNIQUE KEY `refer_code` (`refer_code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create keys_table
CREATE TABLE IF NOT EXISTS `keys_table` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `license_key` varchar(50) NOT NULL,
  `days` bigint(20) NOT NULL,
  `device_limit` bigint(20) NOT NULL,
  `created_by` int(11) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `max_devices` bigint(20) NOT NULL,
  `expires_at` datetime DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT '1',
  PRIMARY KEY (`id`),
  UNIQUE KEY `license_key` (`license_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create key_usage table
CREATE TABLE IF NOT EXISTS `key_usage` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `license_key` varchar(50) NOT NULL,
  `device_id` varchar(255) NOT NULL,
  `used_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create referrals table
CREATE TABLE IF NOT EXISTS `referrals` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `refer_code` varchar(20) NOT NULL,
  `bonus_credits` decimal(15,2) NOT NULL DEFAULT '5.00',
  `created_by` int(11) NOT NULL,
  `used_times` int(11) NOT NULL DEFAULT '0',
  `max_uses` int(11) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT '1',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `refer_code` (`refer_code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create transactions table
CREATE TABLE IF NOT EXISTS `transactions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `from_user` int(11) NOT NULL,
  `to_user` int(11) NOT NULL,
  `amount` decimal(15,2) NOT NULL,
  `type` varchar(20) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Insert admin user (password: password123)
INSERT INTO `users` (`username`, `password_hash`, `role`, `credits`, `refer_code`) VALUES
('ZARUX7', '$2y$12$dqxOISxDYUFi./ncfcV7qeWnty0/1ZajMXQS3/Fw/T0WjAInitn6W', 'admin', 999999.00, 'ADMIN001');

-- Insert referral codes
INSERT INTO `referrals` (`refer_code`, `created_by`, `bonus_credits`) VALUES
('WELCOME100', 1, 10.00),
('VIP2024', 1, 20.00),
('LUNAR50', 1, 5.00);