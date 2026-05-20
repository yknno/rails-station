CREATE DATABASE IF NOT EXISTS `op_development` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE IF NOT EXISTS `hydra` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Allow connections from any host for root user (standard for dev compose, but let's be explicit)
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%';
FLUSH PRIVILEGES;
