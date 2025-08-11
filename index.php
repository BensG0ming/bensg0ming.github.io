<?php
session_start();

// ==================== ERROR HANDLING & DIAGNOSTICS ====================
// Enable error reporting for debugging (remove in production)
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Check PHP version compatibility
if (version_compare(PHP_VERSION, '7.4.0') < 0) {
    die('BensFile requires PHP 7.4 or higher. Current version: ' . PHP_VERSION);
}

// Check required extensions
$required_extensions = ['gd', 'exif', 'fileinfo', 'json'];
$missing_extensions = [];
foreach ($required_extensions as $ext) {
    if (!extension_loaded($ext)) {
        $missing_extensions[] = $ext;
    }
}
if (!empty($missing_extensions)) {
    die('Missing required PHP extensions: ' . implode(', ', $missing_extensions));
}

// Helper function to convert php.ini values to bytes
function convertToBytes($val) {
    if (empty($val)) return 0;
    $val = trim($val);
    $last = strtolower($val[strlen($val)-1]);
    $val = (int)$val;
    switch($last) {
        case 'g': $val *= 1024;
        case 'm': $val *= 1024;
        case 'k': $val *= 1024;
    }
    return $val;
}

// ==================== CONFIGURATION ====================
$config = [
    'uploadDir' => __DIR__ . '/uploads/',
    'maxAge' => 365 * 24 * 60 * 60, // 1 year
    'maxFileSize' => min(
        100 * 1024 * 1024, // 100MB
        min(
            convertToBytes(ini_get('upload_max_filesize')),
            convertToBytes(ini_get('post_max_size'))
        )
    ),
    'allowedTypes' => [
        'image' => ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp', 'tiff', 'ico'],
        'document' => ['pdf', 'doc', 'docx', 'txt', 'rtf', 'odt', 'xls', 'xlsx', 'ppt', 'pptx'],
        'archive' => ['zip', 'rar', '7z', 'tar', 'gz', 'bz2'],
        'audio' => ['mp3', 'wav', 'ogg', 'flac', 'm4a', 'aac', 'wma'],
        'video' => ['mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm', 'm4v'],
        'code' => ['html', 'css', 'js', 'php', 'py', 'java', 'cpp', 'c', 'json', 'xml', 'yaml', 'sql', 'md', 'ts', 'jsx', 'vue', 'go', 'rust', 'swift']
    ],
    'thumbnailDir' => __DIR__ . '/thumbnails/',
    'logFile' => __DIR__ . '/uploads.log'
];

// ==================== DIRECTORY SETUP ====================
function createDirectoriesSafely($config) {
    $errors = [];
    foreach ([$config['uploadDir'], $config['thumbnailDir']] as $dir) {
        if (!file_exists($dir)) {
            if (!@mkdir($dir, 0755, true)) {
                $errors[] = "Failed to create directory: $dir";
                continue;
            }
        }
        
        // Test write permissions
        $testFile = $dir . '.test_write';
        if (!@file_put_contents($testFile, 'test')) {
            $errors[] = "Directory not writable: $dir";
        } else {
            @unlink($testFile);
        }
    }
    return $errors;
}

$dir_errors = createDirectoriesSafely($config);
if (!empty($dir_errors)) {
    die('Directory setup failed:<br>' . implode('<br>', $dir_errors));
}

// Create .htaccess file for better security and performance
$htaccess_content = '
# BensFile .htaccess configuration
RewriteEngine On

# Increase file upload limits (if server allows)
php_value upload_max_filesize 100M
php_value post_max_size 100M
php_value max_execution_time 300
php_value memory_limit 256M

# Security headers
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set X-XSS-Protection "1; mode=block"

# Prevent access to sensitive files
<Files "*.log">
    Deny from all
</Files>

<Files ".uploaders">
    Deny from all
</Files>

# Enable gzip compression
<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/plain text/html text/xml text/css application/xml application/xhtml+xml application/rss+xml application/javascript application/x-javascript
</IfModule>

# Cache static assets
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType image/jpeg "access plus 1 month"
    ExpiresByType image/png "access plus 1 month"
    ExpiresByType image/gif "access plus 1 month"
    ExpiresByType text/css "access plus 1 month"
    ExpiresByType application/javascript "access plus 1 month"
</IfModule>
';

if (!file_exists(__DIR__ . '/.htaccess')) {
    @file_put_contents(__DIR__ . '/.htaccess', $htaccess_content);
}

// ==================== UTILITY FUNCTIONS ====================
function formatBytes($size, $precision = 2) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    for ($i = 0; $size > 1024 && $i < count($units) - 1; $i++) {
        $size /= 1024;
    }
    return round($size, $precision) . ' ' . $units[$i];
}

function getFileType($extension) {
    global $config;
    foreach ($config['allowedTypes'] as $type => $extensions) {
        if (in_array(strtolower($extension), $extensions)) {
            return $type;
        }
    }
    return 'unknown';
}

function getFileIcon($type) {
    $icons = [
        'image' => '🖼️',
        'document' => '📄',
        'archive' => '📦',
        'audio' => '🎵',
        'video' => '🎬',
        'code' => '💻',
        'unknown' => '📁'
    ];
    return $icons[$type] ?? '📁';
}

function logActivity($action, $filename = '', $ip = '') {
    global $config;
    $timestamp = date('Y-m-d H:i:s');
    $ip = $ip ?: $_SERVER['REMOTE_ADDR'];
    $logEntry = "[$timestamp] [$ip] $action";
    if ($filename) $logEntry .= " - $filename";
    $logEntry .= "\n";
    @file_put_contents($config['logFile'], $logEntry, FILE_APPEND | LOCK_EX);
}

function saveUploaderInfo($filename, $sessionId, $ip) {
    global $config;
    $uploaderFile = $config['uploadDir'] . '.uploaders';
    $uploaders = [];
    
    if (file_exists($uploaderFile)) {
        $uploaders = json_decode(file_get_contents($uploaderFile), true) ?: [];
    }
    
    $uploaders[$filename] = [
        'session_id' => $sessionId,
        'ip' => $ip,
        'upload_time' => time()
    ];
    
    @file_put_contents($uploaderFile, json_encode($uploaders), LOCK_EX);
}

function isFileOwner($filename) {
    global $config;
    $uploaderFile = $config['uploadDir'] . '.uploaders';
    
    if (!file_exists($uploaderFile)) {
        return false;
    }
    
    $uploaders = json_decode(file_get_contents($uploaderFile), true) ?: [];
    
    if (!isset($uploaders[$filename])) {
        return false;
    }
    
    $uploader = $uploaders[$filename];
    $currentSessionId = session_id();
    $currentIp = $_SERVER['REMOTE_ADDR'];
    
    return $uploader['session_id'] === $currentSessionId || $uploader['ip'] === $currentIp;
}

function deleteFileAndData($filename) {
    global $config;
    
    $filepath = $config['uploadDir'] . $filename;
    $thumbPath = $config['thumbnailDir'] . $filename . '.jpg';
    $uploaderFile = $config['uploadDir'] . '.uploaders';
    
    $deleted = [];
    
    // Delete main file
    if (file_exists($filepath)) {
        @unlink($filepath);
        $deleted[] = 'file';
    }
    
    // Delete thumbnail
    if (file_exists($thumbPath)) {
        @unlink($thumbPath);
        $deleted[] = 'thumbnail';
    }
    
    // Remove from uploaders list
    if (file_exists($uploaderFile)) {
        $uploaders = json_decode(file_get_contents($uploaderFile), true) ?: [];
        if (isset($uploaders[$filename])) {
            unset($uploaders[$filename]);
            @file_put_contents($uploaderFile, json_encode($uploaders), LOCK_EX);
            $deleted[] = 'metadata';
        }
    }
    
    return $deleted;
}

function createThumbnailSafe($sourcePath, $destPath, $width = 300, $height = 300) {
    try {
        if (!file_exists($sourcePath) || !is_readable($sourcePath)) {
            throw new Exception("Source file not accessible");
        }
        
        if (!extension_loaded('gd')) {
            throw new Exception("GD extension not available");
        }
        
        $imageInfo = @getimagesize($sourcePath);
        if (!$imageInfo) {
            return false;
        }
        
        $sourceWidth = $imageInfo[0];
        $sourceHeight = $imageInfo[1];
        $sourceType = $imageInfo[2];
        
        switch ($sourceType) {
            case IMAGETYPE_JPEG:
                $sourceImage = @imagecreatefromjpeg($sourcePath);
                break;
            case IMAGETYPE_PNG:
                $sourceImage = @imagecreatefrompng($sourcePath);
                break;
            case IMAGETYPE_GIF:
                $sourceImage = @imagecreatefromgif($sourcePath);
                break;
            case IMAGETYPE_WEBP:
                if (function_exists('imagecreatefromwebp')) {
                    $sourceImage = @imagecreatefromwebp($sourcePath);
                } else {
                    return false;
                }
                break;
            default:
                return false;
        }
        
        if (!$sourceImage) return false;
        
        $ratio = min($width / $sourceWidth, $height / $sourceHeight);
        $thumbWidth = (int)($sourceWidth * $ratio);
        $thumbHeight = (int)($sourceHeight * $ratio);
        
        $thumbImage = imagecreatetruecolor($thumbWidth, $thumbHeight);
        if (!$thumbImage) {
            imagedestroy($sourceImage);
            return false;
        }
        
        imagealphablending($thumbImage, false);
        imagesavealpha($thumbImage, true);
        $transparent = imagecolorallocatealpha($thumbImage, 255, 255, 255, 127);
        imagefill($thumbImage, 0, 0, $transparent);
        
        imagecopyresampled($thumbImage, $sourceImage, 0, 0, 0, 0, $thumbWidth, $thumbHeight, $sourceWidth, $sourceHeight);
        
        $saved = @imagejpeg($thumbImage, $destPath, 85);
        
        imagedestroy($sourceImage);
        imagedestroy($thumbImage);
        
        return $saved;
        
    } catch (Exception $e) {
        error_log("Thumbnail creation error: " . $e->getMessage());
        return false;
    }
}

function getImageMetadata($filepath) {
    $metadata = [];
    
    if (function_exists('exif_read_data')) {
        $exif = @exif_read_data($filepath);
        if ($exif) {
            $metadata['camera'] = isset($exif['Make']) ? $exif['Make'] . ' ' . ($exif['Model'] ?? '') : null;
            $metadata['resolution'] = isset($exif['COMPUTED']['Width'], $exif['COMPUTED']['Height']) 
                ? $exif['COMPUTED']['Width'] . 'x' . $exif['COMPUTED']['Height'] : null;
            $metadata['date_taken'] = isset($exif['DateTime']) ? $exif['DateTime'] : null;
            $metadata['iso'] = isset($exif['ISOSpeedRatings']) ? $exif['ISOSpeedRatings'] : null;
            $metadata['aperture'] = isset($exif['COMPUTED']['ApertureFNumber']) ? $exif['COMPUTED']['ApertureFNumber'] : null;
            $metadata['exposure'] = isset($exif['ExposureTime']) ? $exif['ExposureTime'] : null;
            $metadata['focal_length'] = isset($exif['FocalLength']) ? $exif['FocalLength'] : null;
        }
    }
    
    $imageInfo = @getimagesize($filepath);
    if ($imageInfo) {
        $metadata['dimensions'] = $imageInfo[0] . 'x' . $imageInfo[1];
        $metadata['mime_type'] = $imageInfo['mime'];
    }
    
    return $metadata;
}

function cleanExpiredFiles() {
    global $config;
    $count = 0;
    $files = glob($config['uploadDir'] . '*');
    foreach ($files as $file) {
        if (is_file($file) && filemtime($file) < time() - $config['maxAge']) {
            @unlink($file);
            $filename = basename($file);
            $thumbPath = $config['thumbnailDir'] . $filename . '.jpg';
            if (file_exists($thumbPath)) {
                @unlink($thumbPath);
            }
            $count++;
        }
    }
    return $count;
}

// Auto cleanup expired files (1% chance)
if (rand(1, 100) == 1) {
    cleanExpiredFiles();
}

// ==================== REQUEST HANDLERS ====================

// DELETE FILE
if (isset($_GET['delete']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $filename = basename($_GET['delete']);
    $filepath = $config['uploadDir'] . $filename;
    
    if (!file_exists($filepath)) {
        http_response_code(404);
        echo json_encode(['error' => 'File not found']);
        exit;
    }
    
    if (!isFileOwner($filename)) {
        http_response_code(403);
        echo json_encode(['error' => 'Access denied. You can only delete files you uploaded.']);
        exit;
    }
    
    $deleted = deleteFileAndData($filename);
    
    if (in_array('file', $deleted)) {
        logActivity('DELETE', $filename);
        echo json_encode(['success' => true, 'message' => 'File deleted successfully', 'deleted' => $deleted]);
    } else {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to delete file']);
    }
    exit;
}

// GALLERY API
if (isset($_GET['action']) && $_GET['action'] === 'gallery') {
    $files = [];
    $uploadFiles = glob($config['uploadDir'] . '*');
    
    foreach ($uploadFiles as $filepath) {
        if (is_file($filepath)) {
            $filename = basename($filepath);
            $filesize = filesize($filepath);
            $uploadTime = filemtime($filepath);
            $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
            $fileType = getFileType($extension);
            
            if ($uploadTime < time() - $config['maxAge']) {
                continue;
            }
            
            $fileData = [
                'name' => $filename,
                'size' => $filesize,
                'type' => $fileType,
                'icon' => getFileIcon($fileType),
                'upload_time' => $uploadTime,
                'extension' => $extension,
                'has_thumbnail' => file_exists($config['thumbnailDir'] . $filename . '.jpg'),
                'mime_type' => mime_content_type($filepath)
            ];
            
            if ($fileType === 'image') {
                $fileData['metadata'] = getImageMetadata($filepath);
            }
            
            $files[] = $fileData;
        }
    }
    
    usort($files, function($a, $b) {
        return $b['upload_time'] - $a['upload_time'];
    });
    
    header('Content-Type: application/json');
    echo json_encode($files);
    exit;
}

// THUMBNAIL SERVING
if (isset($_GET['thumb'])) {
    $filename = basename($_GET['thumb']);
    $thumbPath = $config['thumbnailDir'] . $filename . '.jpg';
    
    if (file_exists($thumbPath)) {
        header('Content-Type: image/jpeg');
        header('Cache-Control: public, max-age=3600');
        header('Last-Modified: ' . gmdate('D, d M Y H:i:s', filemtime($thumbPath)) . ' GMT');
        readfile($thumbPath);
    } else {
        $filepath = $config['uploadDir'] . $filename;
        if (file_exists($filepath)) {
            $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
            $fileType = getFileType($extension);
            
            header('Content-Type: image/svg+xml');
            $icon = getFileIcon($fileType);
            $colors = [
                'image' => '#ff6b6b',
                'document' => '#4ecdc4',
                'archive' => '#ffe66d',
                'audio' => '#ff8b94',
                'video' => '#a8e6cf',
                'code' => '#ffd93d',
                'unknown' => '#95a5a6'
            ];
            $color = $colors[$fileType] ?? '#95a5a6';
            
            echo '<svg width="300" height="300" viewBox="0 0 300 300" xmlns="http://www.w3.org/2000/svg">
                    <defs>
                        <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
                            <stop offset="0%" style="stop-color:' . $color . ';stop-opacity:0.8" />
                            <stop offset="100%" style="stop-color:' . $color . ';stop-opacity:0.4" />
                        </linearGradient>
                    </defs>
                    <rect width="300" height="300" fill="url(#grad)" rx="15"/>
                    <text x="150" y="180" text-anchor="middle" font-family="Arial" font-size="80" fill="white">' . $icon . '</text>
                    <text x="150" y="240" text-anchor="middle" font-family="Arial" font-size="16" fill="white" opacity="0.8">' . strtoupper($extension) . '</text>
                  </svg>';
        } else {
            http_response_code(404);
        }
    }
    exit;
}

// PREVIEW FILE CONTENT
if (isset($_GET['preview'])) {
    $filename = basename($_GET['preview']);
    $filepath = $config['uploadDir'] . $filename;
    
    if (!file_exists($filepath)) {
        http_response_code(404);
        echo json_encode(['error' => 'File not found']);
        exit;
    }
    
    $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $fileType = getFileType($extension);
    $content = '';
    
    if ($fileType === 'code' || $extension === 'txt') {
        $content = file_get_contents($filepath);
        if (strlen($content) > 10000) {
            $content = substr($content, 0, 10000) . "\n... (truncated)";
        }
    }
    
    header('Content-Type: application/json');
    echo json_encode([
        'type' => $fileType,
        'content' => $content,
        'extension' => $extension
    ]);
    exit;
}

// RAW FILE SERVING
if (isset($_GET['raw'])) {
    $filename = basename($_GET['raw']);
    $filepath = $config['uploadDir'] . $filename;
    
    if (!file_exists($filepath)) {
        http_response_code(404);
        exit;
    }
    
    if (filemtime($filepath) < time() - $config['maxAge']) {
        @unlink($filepath);
        http_response_code(410);
        exit;
    }
    
    $mimeType = mime_content_type($filepath);
    $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    
    header('Content-Type: ' . $mimeType);
    header('Content-Length: ' . filesize($filepath));
    header('Cache-Control: public, max-age=3600');
    header('Last-Modified: ' . gmdate('D, d M Y H:i:s', filemtime($filepath)) . ' GMT');
    
    if (in_array($extension, ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'mp4', 'webm', 'mp3', 'wav', 'ogg'])) {
        header('Content-Disposition: inline; filename="' . $filename . '"');
    }
    
    readfile($filepath);
    exit;
}

// FILE VIEW PAGE
if (isset($_GET['file'])) {
    $filename = basename($_GET['file']);
    $filepath = $config['uploadDir'] . $filename;

    if (!file_exists($filepath)) {
        http_response_code(404);
        $error = ['error' => 'File not found', 'code' => 404];
        if (isset($_GET['api'])) {
            header('Content-Type: application/json');
            echo json_encode($error);
        }
        exit;
    }

    if (filemtime($filepath) < time() - $config['maxAge']) {
        @unlink($filepath);
        http_response_code(410);
        $error = ['error' => 'File expired and deleted', 'code' => 410];
        if (isset($_GET['api'])) {
            header('Content-Type: application/json');
            echo json_encode($error);
        }
        exit;
    }

    $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $fileType = getFileType($extension);
    $mimeType = mime_content_type($filepath);
    
    $fileInfo = [
        'name' => $filename,
        'size' => filesize($filepath),
        'upload_date' => date("d/m/Y H:i", filemtime($filepath)),
        'expire_date' => date("d/m/Y H:i", filemtime($filepath) + $config['maxAge']),
        'download_link' => $_SERVER['PHP_SELF'] . '?download=' . urlencode($filename),
        'raw_link' => $_SERVER['PHP_SELF'] . '?raw=' . urlencode($filename),
        'type' => $fileType,
        'extension' => $extension,
        'mime_type' => $mimeType,
        'has_thumbnail' => file_exists($config['thumbnailDir'] . $filename . '.jpg'),
        'is_owner' => isFileOwner($filename)
    ];

    if ($fileType === 'image') {
        $fileInfo['metadata'] = getImageMetadata($filepath);
    }

    if (isset($_GET['api'])) {
        header('Content-Type: application/json');
        echo json_encode($fileInfo);
        exit;
    }

    logActivity('VIEW', $filename);
}

// DOWNLOAD FILE
if (isset($_GET['download'])) {
    $filename = basename($_GET['download']);
    $filepath = $config['uploadDir'] . $filename;

    if (!file_exists($filepath)) {
        http_response_code(404);
        echo '❌ File not found';
        exit;
    }

    if (filemtime($filepath) < time() - $config['maxAge']) {
        @unlink($filepath);
        http_response_code(410);
        echo '⚠️ File expired and deleted';
        exit;
    }

    logActivity('DOWNLOAD', $filename);

    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($filepath));
    readfile($filepath);
    exit;
}

// UPLOAD PROCESSING
$uploadResult = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['files'])) {
    $uploadResult = ['success' => [], 'errors' => []];
    
    $files = $_FILES['files'];
    $fileCount = is_array($files['name']) ? count($files['name']) : 1;
    
    for ($i = 0; $i < $fileCount; $i++) {
        $file = [
            'name' => is_array($files['name']) ? $files['name'][$i] : $files['name'],
            'type' => is_array($files['type']) ? $files['type'][$i] : $files['type'],
            'tmp_name' => is_array($files['tmp_name']) ? $files['tmp_name'][$i] : $files['tmp_name'],
            'error' => is_array($files['error']) ? $files['error'][$i] : $files['error'],
            'size' => is_array($files['size']) ? $files['size'][$i] : $files['size']
        ];
        
        if ($file['error'] !== 0) {
            $uploadResult['errors'][] = "Error uploading {$file['name']}: Error code {$file['error']}";
            continue;
        }
        
        if ($file['size'] > $config['maxFileSize']) {
            $uploadResult['errors'][] = "File {$file['name']} is too large. Max size: " . formatBytes($config['maxFileSize']);
            continue;
        }
        
        $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        $fileType = getFileType($extension);
        
        if ($fileType === 'unknown') {
            $uploadResult['errors'][] = "File type not allowed: {$file['name']}";
            continue;
        }
        
        $randomName = uniqid() . '_' . time() . '_' . preg_replace('/[^a-zA-Z0-9._-]/', '_', basename($file['name']));
        $dest = $config['uploadDir'] . $randomName;
        
        if (move_uploaded_file($file['tmp_name'], $dest)) {
            saveUploaderInfo($randomName, session_id(), $_SERVER['REMOTE_ADDR']);
            
            if ($fileType === 'image') {
                $thumbPath = $config['thumbnailDir'] . $randomName . '.jpg';
                createThumbnailSafe($dest, $thumbPath);
            }
            
            $url = $_SERVER['PHP_SELF'] . '?file=' . urlencode($randomName);
            
            $uploadResult['success'][] = [
                'original_name' => $file['name'],
                'filename' => $randomName,
                'url' => $url,
                'size' => $file['size'],
                'type' => $fileType
            ];
            
            logActivity('UPLOAD', $file['name'] . ' -> ' . $randomName);
        } else {
            $uploadResult['errors'][] = "Failed to upload {$file['name']}";
        }
    }
}

// STATISTICS
function getStats() {
    global $config;
    $files = glob($config['uploadDir'] . '*');
    $totalFiles = 0;
    $totalSize = 0;
    $typeStats = [];
    
    foreach ($files as $file) {
        if (is_file($file)) {
            $totalFiles++;
            $totalSize += filesize($file);
            
            $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
            $type = getFileType($extension);
            $typeStats[$type] = ($typeStats[$type] ?? 0) + 1;
        }
    }
    
    return [
        'total_files' => $totalFiles,
        'total_size' => $totalSize,
        'type_stats' => $typeStats
    ];
}

$stats = getStats();

// ==================== HTML OUTPUT ====================
?>
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= isset($fileInfo) ? htmlspecialchars($fileInfo['name']) . ' - ' : '' ?>BensFile</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css" rel="stylesheet">
    <style>
        :root {
            --primary: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --secondary: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            --accent: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
            --success: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
            --warning: linear-gradient(135deg, #fce043 0%, #fb7ba2 100%);
            --error: linear-gradient(135deg, #fc466b 0%, #3f5efb 100%);
            --dark: #0d1117;
            --dark-secondary: #161b22;
            --dark-tertiary: #21262d;
            --text: #f0f6fc;
            --text-secondary: #8b949e;
            --text-muted: #6e7681;
            --border: #30363d;
            --glass: rgba(255, 255, 255, 0.1);
            --glow: 0 0 30px rgba(102, 126, 234, 0.3);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'SF Pro Display', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--dark);
            color: var(--text);
            line-height: 1.6;
            overflow-x: hidden;
        }

        .background-effects {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
            opacity: 0.6;
        }

        .bg-orb {
            position: absolute;
            border-radius: 50%;
            background: var(--primary);
            filter: blur(60px);
            animation: float 20s ease-in-out infinite;
        }

        .bg-orb:nth-child(1) {
            width: 300px;
            height: 300px;
            top: 10%;
            left: 10%;
            animation-delay: 0s;
        }

        .bg-orb:nth-child(2) {
            width: 200px;
            height: 200px;
            top: 60%;
            right: 10%;
            background: var(--secondary);
            animation-delay: -7s;
        }

        .bg-orb:nth-child(3) {
            width: 150px;
            height: 150px;
            bottom: 20%;
            left: 60%;
            background: var(--accent);
            animation-delay: -14s;
        }

        @keyframes float {
            0%, 100% { transform: translate(0, 0) rotate(0deg); }
            33% { transform: translate(30px, -30px) rotate(120deg); }
            66% { transform: translate(-20px, 20px) rotate(240deg); }
        }

        /* Navigation */
        .navbar {
            position: fixed;
            top: 20px;
            left: 50%;
            transform: translateX(-50%);
            background: rgba(13, 17, 23, 0.8);
            backdrop-filter: blur(20px);
            border: 1px solid var(--border);
            border-radius: 50px;
            padding: 15px 30px;
            z-index: 1000;
            display: flex;
            align-items: center;
            gap: 30px;
            box-shadow: var(--glow);
        }

        .logo {
            font-size: 1.5rem;
            font-weight: 800;
            background: var(--primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .nav-links {
            display: flex;
            gap: 20px;
            list-style: none;
        }

        .nav-link {
            color: var(--text-secondary);
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 20px;
            transition: all 0.3s ease;
        }

        .nav-link:hover, .nav-link.active {
            color: var(--text);
            background: var(--glass);
        }

        /* Main Container */
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 120px 20px 40px;
        }

        /* File Viewer Styles */
        .file-viewer {
            background: var(--dark-secondary);
            border: 1px solid var(--border);
            border-radius: 20px;
            overflow: hidden;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        }

        .file-header {
            background: var(--dark-tertiary);
            padding: 30px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 20px;
        }

        .file-info {
            display: flex;
            align-items: center;
            gap: 20px;
        }

        .file-icon {
            width: 60px;
            height: 60px;
            background: var(--primary);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2rem;
            color: white;
        }

        .file-details h1 {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 5px;
        }

        .file-meta {
            display: flex;
            gap: 15px;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }

        .file-actions {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }

        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 10px;
            font-weight: 600;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
            font-size: 0.9rem;
        }

        .btn-primary {
            background: var(--primary);
            color: white;
        }

        .btn-secondary {
            background: var(--dark-tertiary);
            color: var(--text);
            border: 1px solid var(--border);
        }

        .btn-success {
            background: var(--success);
            color: white;
        }

        .btn-danger {
            background: var(--error);
            color: white;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
        }

        /* File Content Area */
        .file-content {
            padding: 0;
            min-height: 500px;
            display: flex;
            flex-direction: column;
        }

        .content-tabs {
            display: flex;
            background: var(--dark-tertiary);
            border-bottom: 1px solid var(--border);
        }

        .tab-button {
            padding: 15px 25px;
            background: none;
            border: none;
            color: var(--text-secondary);
            cursor: pointer;
            transition: all 0.3s ease;
            border-bottom: 3px solid transparent;
        }

        .tab-button.active {
            color: var(--text);
            border-bottom-color: #667eea;
            background: var(--glass);
        }

        .tab-content {
            flex: 1;
            padding: 30px;
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        /* Preview Styles */
        .preview-container {
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 400px;
            background: var(--dark);
            border-radius: 15px;
            position: relative;
            overflow: hidden;
        }

        .image-preview {
            max-width: 100%;
            max-height: 70vh;
            border-radius: 10px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
            transition: transform 0.3s ease;
        }

        .image-preview:hover {
            transform: scale(1.02);
        }

        .video-preview {
            width: 100%;
            max-height: 70vh;
            border-radius: 10px;
            background: black;
        }

        .audio-preview {
            width: 100%;
            padding: 40px;
        }

        .audio-visualizer {
            width: 100%;
            height: 200px;
            background: var(--dark-tertiary);
            border-radius: 15px;
            margin-bottom: 20px;
            display: flex;
            align-items: end;
            justify-content: center;
            gap: 3px;
            padding: 20px;
        }

        .audio-bar {
            width: 4px;
            background: var(--primary);
            border-radius: 2px;
            animation: audioWave 1.5s ease-in-out infinite;
        }

        @keyframes audioWave {
            0%, 100% { height: 20px; }
            50% { height: 60px; }
        }

        .code-preview {
            background: #0d1117;
            border-radius: 10px;
            overflow: hidden;
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
        }

        .code-header {
            background: #161b22;
            padding: 15px 20px;
            border-bottom: 1px solid #30363d;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .code-language {
            color: #f0f6fc;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .copy-code-btn {
            padding: 6px 12px;
            background: #21262d;
            border: 1px solid #30363d;
            border-radius: 6px;
            color: #8b949e;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .copy-code-btn:hover {
            background: #30363d;
            color: #f0f6fc;
        }

        .code-content {
            padding: 20px;
            overflow-x: auto;
            max-height: 600px;
            overflow-y: auto;
        }

        .code-content pre {
            margin: 0;
            font-size: 14px;
            line-height: 1.5;
        }

        .document-preview {
            text-align: center;
            padding: 60px 20px;
        }

        .document-icon {
            font-size: 5rem;
            color: #4ecdc4;
            margin-bottom: 20px;
        }

        .document-info {
            color: var(--text-secondary);
        }

        /* Metadata Panel */
        .metadata-panel {
            background: var(--dark);
            border-radius: 15px;
            padding: 25px;
        }

        .metadata-section {
            margin-bottom: 30px;
        }

        .metadata-title {
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 15px;
            color: var(--text);
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .metadata-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }

        .metadata-item {
            background: var(--dark-secondary);
            padding: 15px;
            border-radius: 10px;
            border: 1px solid var(--border);
        }

        .metadata-label {
            font-size: 0.8rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 5px;
        }

        .metadata-value {
            font-weight: 600;
            color: var(--text);
        }

        /* Image Tools */
        .image-tools {
            position: absolute;
            top: 20px;
            right: 20px;
            display: flex;
            gap: 10px;
        }

        .tool-btn {
            width: 40px;
            height: 40px;
            background: rgba(0, 0, 0, 0.7);
            border: none;
            border-radius: 50%;
            color: white;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.3s ease;
        }

        .tool-btn:hover {
            background: rgba(0, 0, 0, 0.9);
            transform: scale(1.1);
        }

        /* Zoom functionality */
        .zoomable {
            cursor: zoom-in;
            transition: transform 0.3s ease;
        }

        .zoomable.zoomed {
            cursor: zoom-out;
            transform: scale(1.5);
        }

        /* Fullscreen styles */
        .fullscreen-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.95);
            z-index: 10000;
            display: none;
            align-items: center;
            justify-content: center;
        }

        .fullscreen-content {
            max-width: 95%;
            max-height: 95%;
            border-radius: 10px;
        }

        .fullscreen-controls {
            position: absolute;
            top: 20px;
            right: 20px;
            display: flex;
            gap: 10px;
        }

        /* Share Modal */
        .modal {
            display: none;
            position: fixed;
            z-index: 9999;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            backdrop-filter: blur(5px);
        }

        .modal-content {
            background: var(--dark-secondary);
            margin: 5% auto;
            padding: 0;
            border-radius: 20px;
            width: 90%;
            max-width: 600px;
            border: 1px solid var(--border);
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
            animation: modalSlideIn 0.3s ease;
        }

        @keyframes modalSlideIn {
            from { opacity: 0; transform: translateY(-50px) scale(0.9); }
            to { opacity: 1; transform: translateY(0) scale(1); }
        }

        .modal-header {
            padding: 25px 30px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .modal-title {
            font-size: 1.3rem;
            font-weight: 600;
        }

        .close-btn {
            background: none;
            border: none;
            font-size: 1.5rem;
            color: var(--text-secondary);
            cursor: pointer;
            transition: color 0.3s ease;
        }

        .close-btn:hover {
            color: var(--text);
        }

        .modal-body {
            padding: 30px;
        }

        .share-options {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }

        .share-option {
            background: var(--dark-tertiary);
            border: 1px solid var(--border);
            border-radius: 15px;
            padding: 20px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            color: var(--text);
        }

        .share-option:hover {
            background: var(--glass);
            transform: translateY(-2px);
        }

        .share-option i {
            font-size: 2rem;
            margin-bottom: 10px;
            display: block;
        }

        .share-url {
            background: var(--dark);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 15px;
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .share-input {
            flex: 1;
            background: none;
            border: none;
            color: var(--text);
            font-size: 0.9rem;
            outline: none;
        }

        .copy-btn {
            background: var(--primary);
            border: none;
            border-radius: 8px;
            padding: 8px 16px;
            color: white;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .copy-btn:hover {
            transform: translateY(-1px);
        }

        /* Back to Gallery */
        .back-btn {
            position: fixed;
            top: 20px;
            left: 20px;
            background: rgba(13, 17, 23, 0.8);
            backdrop-filter: blur(20px);
            border: 1px solid var(--border);
            border-radius: 50px;
            padding: 12px 20px;
            color: var(--text);
            text-decoration: none;
            display: flex;
            align-items: center;
            gap: 10px;
            transition: all 0.3s ease;
            z-index: 1000;
        }

        .back-btn:hover {
            background: var(--glass);
            transform: translateX(-5px);
        }

        /* Loading Animation */
        .loading {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 60px;
        }

        .spinner {
            width: 50px;
            height: 50px;
            border: 3px solid var(--border);
            border-top: 3px solid #667eea;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        /* Upload Section */
        .upload-section {
            background: var(--dark-secondary);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 40px;
            margin-bottom: 40px;
            text-align: center;
        }

        .upload-area {
            border: 2px dashed var(--border);
            border-radius: 15px;
            padding: 60px 20px;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .upload-area:hover,
        .upload-area.dragover {
            border-color: #667eea;
            background: rgba(102, 126, 234, 0.1);
        }

        .upload-icon {
            font-size: 4rem;
            color: #667eea;
            margin-bottom: 20px;
            animation: float 3s ease-in-out infinite;
        }

        .upload-text {
            font-size: 1.2rem;
            margin-bottom: 10px;
        }

        .upload-subtext {
            color: var(--text-secondary);
            margin-bottom: 20px;
        }

        .file-input {
            display: none;
        }

        /* Gallery Grid */
        .gallery-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 25px;
            margin-top: 30px;
        }

        .file-card {
            background: var(--dark-secondary);
            border: 1px solid var(--border);
            border-radius: 15px;
            overflow: hidden;
            transition: all 0.3s ease;
            cursor: pointer;
        }

        .file-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
            border-color: #667eea;
        }

        .file-thumbnail {
            width: 100%;
            height: 200px;
            background: var(--dark);
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            overflow: hidden;
        }

        .file-thumbnail img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }

        .file-card-info {
            padding: 20px;
        }

        .file-name {
            font-weight: 600;
            margin-bottom: 8px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .file-card-meta {
            display: flex;
            justify-content: space-between;
            color: var(--text-secondary);
            font-size: 0.85rem;
        }

        /* Responsive Design */
        @media (max-width: 768px) {
            .container {
                padding: 100px 15px 20px;
            }

            .navbar {
                top: 15px;
                left: 15px;
                right: 15px;
                transform: none;
                padding: 15px 20px;
                flex-direction: column;
                gap: 15px;
            }

            .nav-links {
                justify-content: center;
            }

            .file-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 20px;
            }

            .file-actions {
                width: 100%;
                justify-content: center;
            }

            .gallery-grid {
                grid-template-columns: 1fr;
            }

            .back-btn {
                position: static;
                margin-bottom: 20px;
                align-self: flex-start;
            }
        }

        /* Notification */
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--success);
            color: white;
            padding: 15px 25px;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            transform: translateX(400px);
            transition: transform 0.3s ease;
            z-index: 10001;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .notification.show {
            transform: translateX(0);
        }

        .notification.error {
            background: var(--error);
        }

        .notification.info {
            background: var(--accent);
        }

        /* Syntax highlighting overrides */
        .token.comment { color: #6e7681; }
        .token.keyword { color: #ff7b72; }
        .token.string { color: #a5d6ff; }
        .token.function { color: #d2a8ff; }
        .token.number { color: #79c0ff; }
        .token.operator { color: #ff7b72; }
        .token.punctuation { color: #f0f6fc; }
    </style>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-core.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/plugins/autoloader/prism-autoloader.min.js"></script>
</head>
<body>
    <div class="background-effects">
        <div class="bg-orb"></div>
        <div class="bg-orb"></div>
        <div class="bg-orb"></div>
    </div>

    <?php if (isset($fileInfo)): ?>
        <!-- FILE VIEWER PAGE -->
        <a href="<?= $_SERVER['PHP_SELF'] ?>" class="back-btn">
            <i class="fas fa-arrow-left"></i>
            Back to Gallery
        </a>

        <div class="container">
            <div class="file-viewer">
                <div class="file-header">
                    <div class="file-info">
                        <div class="file-icon">
                            <?= getFileIcon($fileInfo['type']) ?>
                        </div>
                        <div class="file-details">
                            <h1><?= htmlspecialchars($fileInfo['name']) ?></h1>
                            <div class="file-meta">
                                <span><i class="fas fa-hdd"></i> <?= formatBytes($fileInfo['size']) ?></span>
                                <span><i class="fas fa-calendar"></i> <?= $fileInfo['upload_date'] ?></span>
                                <span><i class="fas fa-clock"></i> Expires <?= $fileInfo['expire_date'] ?></span>
                                <span><i class="fas fa-tag"></i> <?= strtoupper($fileInfo['extension']) ?></span>
                            </div>
                        </div>
                    </div>
                    <div class="file-actions">
                        <a href="<?= $fileInfo['download_link'] ?>" class="btn btn-primary">
                            <i class="fas fa-download"></i> Download
                        </a>
                        <button class="btn btn-secondary" onclick="shareFile()">
                            <i class="fas fa-share-alt"></i> Share
                        </button>
                        <button class="btn btn-secondary" onclick="toggleFullscreen()">
                            <i class="fas fa-expand"></i> Fullscreen
                        </button>
                        <?php if ($fileInfo['is_owner']): ?>
                        <button class="btn btn-danger" onclick="deleteFile()" title="Delete file (you uploaded this)">
                            <i class="fas fa-trash-alt"></i> Delete
                        </button>
                        <?php endif; ?>
                    </div>
                </div>

                <div class="file-content">
                    <div class="content-tabs">
                        <button class="tab-button active" onclick="showTab('preview')">
                            <i class="fas fa-eye"></i> Preview
                        </button>
                        <button class="tab-button" onclick="showTab('metadata')">
                            <i class="fas fa-info-circle"></i> Details
                        </button>
                        <?php if ($fileInfo['type'] === 'code' || $fileInfo['extension'] === 'txt'): ?>
                        <button class="tab-button" onclick="showTab('raw')">
                            <i class="fas fa-code"></i> Raw Content
                        </button>
                        <?php endif; ?>
                    </div>

                    <!-- Preview Tab -->
                    <div class="tab-content active" id="preview-tab">
                        <div class="preview-container" id="previewContainer">
                            <?php if ($fileInfo['type'] === 'image'): ?>
                                <div class="image-tools">
                                    <button class="tool-btn" onclick="zoomImage()" title="Zoom">
                                        <i class="fas fa-search-plus"></i>
                                    </button>
                                    <button class="tool-btn" onclick="downloadImage()" title="Download">
                                        <i class="fas fa-download"></i>
                                    </button>
                                </div>
                                <img src="<?= $fileInfo['raw_link'] ?>" alt="<?= htmlspecialchars($fileInfo['name']) ?>" 
                                     class="image-preview zoomable" id="mainImage" onclick="zoomImage()">
                            <?php elseif ($fileInfo['type'] === 'video'): ?>
                                <video controls class="video-preview">
                                    <source src="<?= $fileInfo['raw_link'] ?>" type="<?= $fileInfo['mime_type'] ?>">
                                    Your browser does not support the video tag.
                                </video>
                            <?php elseif ($fileInfo['type'] === 'audio'): ?>
                                <div class="audio-preview">
                                    <div class="audio-visualizer">
                                        <?php for ($i = 0; $i < 50; $i++): ?>
                                            <div class="audio-bar" style="animation-delay: <?= $i * 0.05 ?>s; height: <?= rand(20, 80) ?>px;"></div>
                                        <?php endfor; ?>
                                    </div>
                                    <audio controls style="width: 100%;">
                                        <source src="<?= $fileInfo['raw_link'] ?>" type="<?= $fileInfo['mime_type'] ?>">
                                        Your browser does not support the audio element.
                                    </audio>
                                </div>
                            <?php elseif ($fileInfo['type'] === 'code' || $fileInfo['extension'] === 'txt'): ?>
                                <div class="loading" id="codeLoading">
                                    <div class="spinner"></div>
                                </div>
                                <div class="code-preview" id="codePreview" style="display: none;">
                                    <div class="code-header">
                                        <div class="code-language">
                                            <i class="fas fa-code"></i>
                                            <span id="languageName"><?= strtoupper($fileInfo['extension']) ?></span>
                                        </div>
                                        <button class="copy-code-btn" onclick="copyCode()">
                                            <i class="fas fa-copy"></i> Copy
                                        </button>
                                    </div>
                                    <div class="code-content">
                                        <pre><code id="codeContent"></code></pre>
                                    </div>
                                </div>
                            <?php else: ?>
                                <div class="document-preview">
                                    <div class="document-icon">
                                        <?= getFileIcon($fileInfo['type']) ?>
                                    </div>
                                    <h3><?= htmlspecialchars($fileInfo['name']) ?></h3>
                                    <p class="document-info">
                                        This file type cannot be previewed directly.<br>
                                        Click the download button to save it to your device.
                                    </p>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>

                    <!-- Metadata Tab -->
                    <div class="tab-content" id="metadata-tab">
                        <div class="metadata-panel">
                            <div class="metadata-section">
                                <div class="metadata-title">
                                    <i class="fas fa-file"></i>
                                    File Information
                                </div>
                                <div class="metadata-grid">
                                    <div class="metadata-item">
                                        <div class="metadata-label">File Name</div>
                                        <div class="metadata-value"><?= htmlspecialchars($fileInfo['name']) ?></div>
                                    </div>
                                    <div class="metadata-item">
                                        <div class="metadata-label">File Size</div>
                                        <div class="metadata-value"><?= formatBytes($fileInfo['size']) ?></div>
                                    </div>
                                    <div class="metadata-item">
                                        <div class="metadata-label">File Type</div>
                                        <div class="metadata-value"><?= ucfirst($fileInfo['type']) ?></div>
                                    </div>
                                    <div class="metadata-item">
                                        <div class="metadata-label">Extension</div>
                                        <div class="metadata-value"><?= strtoupper($fileInfo['extension']) ?></div>
                                    </div>
                                    <div class="metadata-item">
                                        <div class="metadata-label">MIME Type</div>
                                        <div class="metadata-value"><?= $fileInfo['mime_type'] ?></div>
                                    </div>
                                    <div class="metadata-item">
                                        <div class="metadata-label">Upload Date</div>
                                        <div class="metadata-value"><?= $fileInfo['upload_date'] ?></div>
                                    </div>
                                    <div class="metadata-item">
                                        <div class="metadata-label">Expires On</div>
                                        <div class="metadata-value"><?= $fileInfo['expire_date'] ?></div>
                                    </div>
                                </div>
                            </div>

                            <?php if (isset($fileInfo['metadata']) && !empty($fileInfo['metadata'])): ?>
                            <div class="metadata-section">
                                <div class="metadata-title">
                                    <i class="fas fa-camera"></i>
                                    Image Metadata
                                </div>
                                <div class="metadata-grid">
                                    <?php foreach ($fileInfo['metadata'] as $key => $value): ?>
                                        <?php if ($value): ?>
                                        <div class="metadata-item">
                                            <div class="metadata-label"><?= ucfirst(str_replace('_', ' ', $key)) ?></div>
                                            <div class="metadata-value"><?= htmlspecialchars($value) ?></div>
                                        </div>
                                        <?php endif; ?>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                            <?php endif; ?>

                            <div class="metadata-section">
                                <div class="metadata-title">
                                    <i class="fas fa-link"></i>
                                    Links & Access
                                </div>
                                <div class="metadata-grid">
                                    <div class="metadata-item">
                                        <div class="metadata-label">Direct Link</div>
                                        <div class="metadata-value" style="word-break: break-all; font-size: 0.8rem;">
                                            <?= $_SERVER['HTTP_HOST'] . $fileInfo['raw_link'] ?>
                                        </div>
                                    </div>
                                    <div class="metadata-item">
                                        <div class="metadata-label">Download Link</div>
                                        <div class="metadata-value" style="word-break: break-all; font-size: 0.8rem;">
                                            <?= $_SERVER['HTTP_HOST'] . $fileInfo['download_link'] ?>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Raw Content Tab -->
                    <?php if ($fileInfo['type'] === 'code' || $fileInfo['extension'] === 'txt'): ?>
                    <div class="tab-content" id="raw-tab">
                        <div class="loading" id="rawLoading">
                            <div class="spinner"></div>
                        </div>
                        <div class="code-preview" id="rawPreview" style="display: none;">
                            <div class="code-header">
                                <div class="code-language">
                                    <i class="fas fa-file-code"></i>
                                    <span>Raw Content</span>
                                </div>
                                <button class="copy-code-btn" onclick="copyRawCode()">
                                    <i class="fas fa-copy"></i> Copy All
                                </button>
                            </div>
                            <div class="code-content">
                                <pre><code id="rawContent"></code></pre>
                            </div>
                        </div>
                    </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- Fullscreen Overlay -->
        <div class="fullscreen-overlay" id="fullscreenOverlay">
            <div class="fullscreen-controls">
                <button class="tool-btn" onclick="toggleFullscreen()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div id="fullscreenContent"></div>
        </div>

    <?php else: ?>
        <!-- GALLERY PAGE -->
        <nav class="navbar">
            <div class="logo">🚀 BensFile</div>
            <ul class="nav-links">
                <li><a href="#" class="nav-link active">Gallery</a></li>
                <li><a href="#upload" class="nav-link">Upload</a></li>
                <li><a href="#stats" class="nav-link">Stats</a></li>
            </ul>
        </nav>

        <div class="container">
            <div class="upload-section" id="upload">
                <h2 style="margin-bottom: 30px; font-size: 2rem; background: var(--primary); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
                    Upload Your Files
                </h2>
                <div class="upload-area" id="uploadArea" onclick="document.getElementById('fileInput').click()">
                    <div class="upload-icon">
                        <i class="fas fa-cloud-upload-alt"></i>
                    </div>
                    <div class="upload-text">Drag & drop files here</div>
                    <div class="upload-subtext">or click to browse (Max: <?= formatBytes($config['maxFileSize']) ?>)</div>
                    <input type="file" id="fileInput" class="file-input" multiple>
                </div>
                
                <?php if ($uploadResult): ?>
                <div class="upload-results" style="margin-top: 30px;">
                    <?php if (!empty($uploadResult['success'])): ?>
                        <div class="success-results">
                            <h3 style="color: #38ef7d; margin-bottom: 15px;">✅ Successfully uploaded:</h3>
                            <?php foreach ($uploadResult['success'] as $file): ?>
                                <div style="background: var(--dark); padding: 15px; border-radius: 10px; margin-bottom: 10px;">
                                    <strong><?= htmlspecialchars($file['original_name']) ?></strong>
                                    <br>
                                    <small>Type: <?= ucfirst($file['type']) ?> | Size: <?= formatBytes($file['size']) ?></small>
                                    <br>
                                    <a href="<?= $file['url'] ?>" style="color: #667eea;">View File →</a>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                    
                    <?php if (!empty($uploadResult['errors'])): ?>
                        <div class="error-results">
                            <h3 style="color: #fc466b; margin-bottom: 15px;">❌ Upload errors:</h3>
                            <?php foreach ($uploadResult['errors'] as $error): ?>
                                <div style="background: rgba(252, 70, 107, 0.1); padding: 15px; border-radius: 10px; margin-bottom: 10px; border-left: 4px solid #fc466b;">
                                    <?= htmlspecialchars($error) ?>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                </div>
                <?php endif; ?>
            </div>

            <!-- Stats Section -->
            <div id="stats" class="upload-section">
                <h2 style="margin-bottom: 30px; font-size: 2rem; background: var(--accent); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
                    📊 Statistics
                </h2>
                <div class="metadata-grid">
                    <div class="metadata-item">
                        <div class="metadata-label">Total Files</div>
                        <div class="metadata-value"><?= number_format($stats['total_files']) ?></div>
                    </div>
                    <div class="metadata-item">
                        <div class="metadata-label">Total Size</div>
                        <div class="metadata-value"><?= formatBytes($stats['total_size']) ?></div>
                    </div>
                    <div class="metadata-item">
                        <div class="metadata-label">Max File Size</div>
                        <div class="metadata-value"><?= formatBytes($config['maxFileSize']) ?></div>
                    </div>
                    <div class="metadata-item">
                        <div class="metadata-label">File Retention</div>
                        <div class="metadata-value"><?= $config['maxAge'] / (24 * 60 * 60) ?> days</div>
                    </div>
                </div>
                
                <?php if (!empty($stats['type_stats'])): ?>
                <h3 style="margin: 30px 0 20px 0; color: var(--text-secondary);">File Types:</h3>
                <div class="metadata-grid">
                    <?php foreach ($stats['type_stats'] as $type => $count): ?>
                    <div class="metadata-item">
                        <div class="metadata-label"><?= getFileIcon($type) ?> <?= ucfirst($type) ?></div>
                        <div class="metadata-value"><?= number_format($count) ?> files</div>
                    </div>
                    <?php endforeach; ?>
                </div>
                <?php endif; ?>
            </div>

            <h2 style="margin-bottom: 30px; font-size: 2rem; background: var(--primary); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
                📁 Your Files
            </h2>
            
            <div class="gallery-grid" id="galleryGrid">
                <div class="loading">
                    <div class="spinner"></div>
                </div>
            </div>
        </div>
    <?php endif; ?>

    <!-- Share Modal -->
    <div class="modal" id="shareModal">
        <div class="modal-content">
            <div class="modal-header">
                <div class="modal-title">Share File</div>
                <button class="close-btn" onclick="closeShareModal()">&times;</button>
            </div>
            <div class="modal-body">
                <div class="share-options">
                    <a href="#" class="share-option" onclick="shareVia('email')">
                        <i class="fas fa-envelope" style="color: #ea4335;"></i>
                        <span>Email</span>
                    </a>
                    <a href="#" class="share-option" onclick="shareVia('twitter')">
                        <i class="fab fa-twitter" style="color: #1da1f2;"></i>
                        <span>Twitter</span>
                    </a>
                    <a href="#" class="share-option" onclick="shareVia('facebook')">
                        <i class="fab fa-facebook" style="color: #4267b2;"></i>
                        <span>Facebook</span>
                    </a>
                    <a href="#" class="share-option" onclick="shareVia('telegram')">
                        <i class="fab fa-telegram" style="color: #0088cc;"></i>
                        <span>Telegram</span>
                    </a>
                    <a href="#" class="share-option" onclick="shareVia('whatsapp')">
                        <i class="fab fa-whatsapp" style="color: #25d366;"></i>
                        <span>WhatsApp</span>
                    </a>
                    <a href="#" class="share-option" onclick="shareVia('copy')">
                        <i class="fas fa-copy" style="color: #6c757d;"></i>
                        <span>Copy Link</span>
                    </a>
                </div>
                
                <div style="margin-top: 30px;">
                    <label style="display: block; margin-bottom: 10px; font-weight: 600;">Direct Link:</label>
                    <div class="share-url">
                        <input type="text" class="share-input" id="shareInput" readonly>
                        <button class="copy-btn" onclick="copyShareLink()">
                            <i class="fas fa-copy"></i> Copy
                        </button>
                    </div>
                </div>

                <div style="margin-top: 20px;">
                    <label style="display: block; margin-bottom: 10px; font-weight: 600;">Embed Code:</label>
                    <div class="share-url">
                        <input type="text" class="share-input" id="embedInput" readonly>
                        <button class="copy-btn" onclick="copyEmbedCode()">
                            <i class="fas fa-code"></i> Copy
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Delete Confirmation Modal -->
    <div class="modal" id="deleteModal">
        <div class="modal-content">
            <div class="modal-header">
                <div class="modal-title">
                    <i class="fas fa-exclamation-triangle" style="color: #f56565; margin-right: 10px;"></i>
                    Delete File
                </div>
                <button class="close-btn" onclick="closeDeleteModal()">&times;</button>
            </div>
            <div class="modal-body">
                <p style="margin-bottom: 20px; font-size: 1.1rem;">
                    Are you sure you want to delete this file?
                </p>
                <div style="background: var(--dark); padding: 20px; border-radius: 10px; margin-bottom: 30px;">
                    <div style="display: flex; align-items: center; gap: 15px;">
                        <div style="font-size: 2rem;" id="deleteFileIcon"><?= isset($fileInfo) ? getFileIcon($fileInfo['type']) : '' ?></div>
                        <div>
                            <div style="font-weight: 600; margin-bottom: 5px;" id="deleteFileName"></div>
                            <div style="color: var(--text-secondary); font-size: 0.9rem;" id="deleteFileInfo"></div>
                        </div>
                    </div>
                </div>
                <p style="color: var(--text-secondary); margin-bottom: 30px;">
                    <i class="fas fa-info-circle"></i>
                    This action cannot be undone. The file will be permanently deleted from our servers.
                </p>
                <div style="display: flex; gap: 15px; justify-content: flex-end;">
                    <button class="btn btn-secondary" onclick="closeDeleteModal()">
                        <i class="fas fa-times"></i> Cancel
                    </button>
                    <button class="btn btn-danger" onclick="confirmDelete()">
                        <i class="fas fa-trash-alt"></i> Delete File
                    </button>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Global variables
        let currentFile = <?= isset($fileInfo) ? json_encode($fileInfo) : 'null' ?>;
        let isZoomed = false;
        let allFiles = [];

        // Initialize app
        document.addEventListener('DOMContentLoaded', function() {
            if (currentFile) {
                initFileViewer();
            } else {
                initGallery();
            }
            setupEventListeners();
        });

        function setupEventListeners() {
            // File upload
            if (document.getElementById('fileInput')) {
                document.getElementById('fileInput').addEventListener('change', handleFileUpload);
                setupDragAndDrop();
            }

            // Keyboard shortcuts
            document.addEventListener('keydown', function(e) {
                if (e.key === 'Escape') {
                    if (document.getElementById('fullscreenOverlay').style.display === 'flex') {
                        toggleFullscreen();
                    } else if (document.getElementById('shareModal').style.display === 'block') {
                        closeShareModal();
                    } else if (document.getElementById('deleteModal').style.display === 'block') {
                        closeDeleteModal();
                    }
                }
                if (e.key === 'f' || e.key === 'F') {
                    if (currentFile && (currentFile.type === 'image' || currentFile.type === 'video')) {
                        toggleFullscreen();
                    }
                }
            });

            // Close modals on outside click
            document.getElementById('shareModal').addEventListener('click', function(e) {
                if (e.target === this) closeShareModal();
            });

            document.getElementById('deleteModal').addEventListener('click', function(e) {
                if (e.target === this) closeDeleteModal();
            });

            document.getElementById('fullscreenOverlay').addEventListener('click', function(e) {
                if (e.target === this) toggleFullscreen();
            });
        }

        function initFileViewer() {
            // Load code content if it's a code file
            if (currentFile.type === 'code' || currentFile.extension === 'txt') {
                loadCodeContent();
            }

            // Auto-generate audio visualization
            if (currentFile.type === 'audio') {
                animateAudioBars();
            }
        }

        function initGallery() {
            loadGallery();
        }

        function loadGallery() {
            fetch('?action=gallery')
                .then(response => response.json())
                .then(files => {
                    allFiles = files;
                    displayGallery(files);
                })
                .catch(error => {
                    console.error('Error loading gallery:', error);
                    document.getElementById('galleryGrid').innerHTML = `
                        <div style="grid-column: 1 / -1; text-align: center; padding: 60px; color: var(--text-secondary);">
                            <i class="fas fa-exclamation-triangle" style="font-size: 3rem; margin-bottom: 20px; color: #f56565;"></i>
                            <h3>Error loading files</h3>
                            <p>Please try again later</p>
                        </div>
                    `;
                });
        }

        function displayGallery(files) {
            const grid = document.getElementById('galleryGrid');
            
            if (files.length === 0) {
                grid.innerHTML = `
                    <div style="grid-column: 1 / -1; text-align: center; padding: 60px; color: var(--text-secondary);">
                        <i class="fas fa-folder-open" style="font-size: 4rem; margin-bottom: 20px; opacity: 0.5;"></i>
                        <h3>No files yet</h3>
                        <p>Upload your first file to get started!</p>
                    </div>
                `;
                return;
            }

            grid.innerHTML = files.map(file => `
                <div class="file-card" onclick="viewFile('${file.name}')">
                    <div class="file-thumbnail">
                        ${file.has_thumbnail ? 
                            `<img src="?thumb=${encodeURIComponent(file.name)}" alt="Thumbnail" loading="lazy">` :
                            `<i class="fas fa-file" style="font-size: 3rem; color: var(--text-secondary);"></i>`
                        }
                    </div>
                    <div class="file-card-info">
                        <div class="file-name" title="${file.name}">${file.name}</div>
                        <div class="file-card-meta">
                            <span>${formatBytes(file.size)}</span>
                            <span>${new Date(file.upload_time * 1000).toLocaleDateString()}</span>
                        </div>
                    </div>
                </div>
            `).join('');
        }

        function viewFile(filename) {
            window.location.href = `?file=${encodeURIComponent(filename)}`;
        }

        function showTab(tabName) {
            // Update tab buttons
            document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');

            // Update tab content
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
            document.getElementById(tabName + '-tab').classList.add('active');

            // Load content if needed
            if (tabName === 'raw' && currentFile && (currentFile.type === 'code' || currentFile.extension === 'txt')) {
                loadRawContent();
            }
        }

        function loadCodeContent() {
            fetch(`?preview=${encodeURIComponent(currentFile.name)}`)
                .then(response => response.json())
                .then(data => {
                    document.getElementById('codeLoading').style.display = 'none';
                    document.getElementById('codePreview').style.display = 'block';
                    
                    const codeElement = document.getElementById('codeContent');
                    codeElement.textContent = data.content;
                    codeElement.className = `language-${getLanguageClass(data.extension)}`;
                    
                    // Apply syntax highlighting
                    if (window.Prism) {
                        Prism.highlightElement(codeElement);
                    }
                })
                .catch(error => {
                    console.error('Error loading code:', error);
                    document.getElementById('codeLoading').innerHTML = `
                        <div style="color: var(--error-color); text-align: center;">
                            <i class="fas fa-exclamation-triangle"></i>
                            <p>Error loading file content</p>
                        </div>
                    `;
                });
        }

        function loadRawContent() {
            const rawLoading = document.getElementById('rawLoading');
            const rawPreview = document.getElementById('rawPreview');
            
            if (rawPreview.dataset.loaded) return;

            fetch(currentFile.raw_link)
                .then(response => response.text())
                .then(content => {
                    rawLoading.style.display = 'none';
                    rawPreview.style.display = 'block';
                    rawPreview.dataset.loaded = 'true';
                    
                    const codeElement = document.getElementById('rawContent');
                    codeElement.textContent = content;
                })
                .catch(error => {
                    console.error('Error loading raw content:', error);
                    rawLoading.innerHTML = `
                        <div style="color: var(--error-color); text-align: center;">
                            <i class="fas fa-exclamation-triangle"></i>
                            <p>Error loading raw content</p>
                        </div>
                    `;
                });
        }

        function getLanguageClass(extension) {
            const languageMap = {
                'js': 'javascript',
                'ts': 'typescript',
                'py': 'python',
                'rb': 'ruby',
                'php': 'php',
                'java': 'java',
                'cpp': 'cpp',
                'c': 'c',
                'cs': 'csharp',
                'go': 'go',
                'rs': 'rust',
                'swift': 'swift',
                'kt': 'kotlin',
                'html': 'html',
                'css': 'css',
                'scss': 'scss',
                'json': 'json',
                'xml': 'xml',
                'yaml': 'yaml',
                'yml': 'yaml',
                'sql': 'sql',
                'md': 'markdown',
                'sh': 'bash',
                'vue': 'vue',
                'jsx': 'jsx',
                'tsx': 'tsx'
            };
            return languageMap[extension.toLowerCase()] || 'text';
        }

        function zoomImage() {
            const image = document.getElementById('mainImage');
            if (isZoomed) {
                image.classList.remove('zoomed');
                isZoomed = false;
            } else {
                image.classList.add('zoomed');
                isZoomed = true;
            }
        }

        function downloadImage() {
            const link = document.createElement('a');
            link.href = currentFile.download_link;
            link.download = currentFile.name;
            link.click();
        }

        function toggleFullscreen() {
            const overlay = document.getElementById('fullscreenOverlay');
            const content = document.getElementById('fullscreenContent');
            
            if (overlay.style.display === 'flex') {
                overlay.style.display = 'none';
                content.innerHTML = '';
            } else {
                overlay.style.display = 'flex';
                
                if (currentFile.type === 'image') {
                    content.innerHTML = `<img src="${currentFile.raw_link}" class="fullscreen-content" alt="${currentFile.name}">`;
                } else if (currentFile.type === 'video') {
                    content.innerHTML = `
                        <video class="fullscreen-content" controls autoplay>
                            <source src="${currentFile.raw_link}" type="${currentFile.mime_type}">
                        </video>
                    `;
                }
            }
        }

        function shareFile() {
            const modal = document.getElementById('shareModal');
            const shareInput = document.getElementById('shareInput');
            const embedInput = document.getElementById('embedInput');
            
            const fileUrl = window.location.origin + window.location.pathname + '?file=' + encodeURIComponent(currentFile.name);
            shareInput.value = fileUrl;
            
            // Generate embed code based on file type
            let embedCode = '';
            if (currentFile.type === 'image') {
                embedCode = `<img src="${window.location.origin}${currentFile.raw_link}" alt="${currentFile.name}" style="max-width: 100%; height: auto;">`;
            } else if (currentFile.type === 'video') {
                embedCode = `<video controls style="max-width: 100%; height: auto;"><source src="${window.location.origin}${currentFile.raw_link}" type="${currentFile.mime_type}"></video>`;
            } else if (currentFile.type === 'audio') {
                embedCode = `<audio controls><source src="${window.location.origin}${currentFile.raw_link}" type="${currentFile.mime_type}"></audio>`;
            } else {
                embedCode = `<a href="${fileUrl}" target="_blank">${currentFile.name}</a>`;
            }
            embedInput.value = embedCode;
            
            modal.style.display = 'block';
        }

        function closeShareModal() {
            document.getElementById('shareModal').style.display = 'none';
        }

        function deleteFile() {
            if (!currentFile || !currentFile.is_owner) {
                showNotification('You can only delete files you uploaded.', 'error');
                return;
            }
            
            // Show delete confirmation modal
            document.getElementById('deleteFileName').textContent = currentFile.name;
            document.getElementById('deleteFileInfo').textContent = `${formatBytes(currentFile.size)} • Uploaded ${currentFile.upload_date}`;
            document.getElementById('deleteModal').style.display = 'block';
        }

        function closeDeleteModal() {
            document.getElementById('deleteModal').style.display = 'none';
        }

        function confirmDelete() {
            if (!currentFile || !currentFile.is_owner) {
                showNotification('Access denied.', 'error');
                return;
            }
            
            // Show loading
            showNotification('Deleting file...', 'info');
            closeDeleteModal();
            
            // Send delete request
            fetch(`?delete=${encodeURIComponent(currentFile.name)}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification('File deleted successfully!', 'success');
                    // Redirect to gallery after 1 second
                    setTimeout(() => {
                        window.location.href = window.location.pathname;
                    }, 1000);
                } else {
                    throw new Error(data.error || 'Delete failed');
                }
            })
            .catch(error => {
                console.error('Delete error:', error);
                showNotification(error.message || 'Failed to delete file. Please try again.', 'error');
            });
        }

        function shareVia(platform) {
            const fileUrl = encodeURIComponent(window.location.origin + window.location.pathname + '?file=' + encodeURIComponent(currentFile.name));
            const fileName = encodeURIComponent(currentFile.name);
            const text = encodeURIComponent(`Check out this file: ${currentFile.name}`);
            
            let shareUrl = '';
            
            switch (platform) {
                case 'email':
                    shareUrl = `mailto:?subject=${fileName}&body=${text}%20${fileUrl}`;
                    break;
                case 'twitter':
                    shareUrl = `https://twitter.com/intent/tweet?text=${text}&url=${fileUrl}`;
                    break;
                case 'facebook':
                    shareUrl = `https://www.facebook.com/sharer/sharer.php?u=${fileUrl}`;
                    break;
                case 'telegram':
                    shareUrl = `https://t.me/share/url?url=${fileUrl}&text=${text}`;
                    break;
                case 'whatsapp':
                    shareUrl = `https://wa.me/?text=${text}%20${fileUrl}`;
                    break;
                case 'copy':
                    copyToClipboard(decodeURIComponent(fileUrl));
                    return;
            }
            
            window.open(shareUrl, '_blank');
        }

        function copyShareLink() {
            const input = document.getElementById('shareInput');
            input.select();
            document.execCommand('copy');
            showNotification('Link copied to clipboard!');
        }

        function copyEmbedCode() {
            const input = document.getElementById('embedInput');
            input.select();
            document.execCommand('copy');
            showNotification('Embed code copied to clipboard!');
        }

        function copyCode() {
            const codeElement = document.getElementById('codeContent');
            copyToClipboard(codeElement.textContent);
        }

        function copyRawCode() {
            const codeElement = document.getElementById('rawContent');
            copyToClipboard(codeElement.textContent);
        }

        function copyToClipboard(text) {
            if (navigator.clipboard) {
                navigator.clipboard.writeText(text).then(() => {
                    showNotification('Copied to clipboard!');
                });
            } else {
                // Fallback
                const textArea = document.createElement('textarea');
                textArea.value = text;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                showNotification('Copied to clipboard!');
            }
        }

        function animateAudioBars() {
            const bars = document.querySelectorAll('.audio-bar');
            setInterval(() => {
                bars.forEach(bar => {
                    bar.style.height = Math.random() * 60 + 20 + 'px';
                });
            }, 300);
        }

        // File upload functionality
        function setupDragAndDrop() {
            const uploadArea = document.getElementById('uploadArea');
            
            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
                uploadArea.addEventListener(eventName, preventDefaults, false);
            });

            function preventDefaults(e) {
                e.preventDefault();
                e.stopPropagation();
            }

            ['dragenter', 'dragover'].forEach(eventName => {
                uploadArea.addEventListener(eventName, highlight, false);
            });

            ['dragleave', 'drop'].forEach(eventName => {
                uploadArea.addEventListener(eventName, unhighlight, false);
            });

            function highlight() {
                uploadArea.classList.add('dragover');
            }

            function unhighlight() {
                uploadArea.classList.remove('dragover');
            }

            uploadArea.addEventListener('drop', handleDrop, false);
        }

        function handleDrop(e) {
            const files = e.dataTransfer.files;
            handleFileUpload({ target: { files } });
        }

        function handleFileUpload(e) {
            const files = e.target.files;
            if (files.length === 0) return;

            const formData = new FormData();
            for (let i = 0; i < files.length; i++) {
                formData.append('files[]', files[i]);
            }

            // Show upload progress
            showNotification('Uploading files...', 'info');

            fetch(window.location.pathname, {
                method: 'POST',
                body: formData
            })
            .then(response => response.text())
            .then(() => {
                showNotification('Files uploaded successfully!', 'success');
                // Reload page to show results
                setTimeout(() => window.location.reload(), 1000);
            })
            .catch(error => {
                console.error('Upload error:', error);
                showNotification('Upload failed. Please try again.', 'error');
            });
        }

        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function showNotification(message, type = 'success') {
            // Remove existing notifications
            document.querySelectorAll('.notification').forEach(n => n.remove());
            
            const notification = document.createElement('div');
            notification.className = `notification ${type}`;
            notification.innerHTML = `
                <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
                <span>${message}</span>
            `;
            
            document.body.appendChild(notification);
            
            setTimeout(() => notification.classList.add('show'), 100);
            
            setTimeout(() => {
                notification.classList.remove('show');
                setTimeout(() => notification.remove(), 300);
            }, 3000);
        }

        // Smooth scrolling for navigation
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });

        // Add some sparkle effects
        function createSparkle() {
            const sparkle = document.createElement('div');
            sparkle.style.position = 'fixed';
            sparkle.style.width = '4px';
            sparkle.style.height = '4px';
            sparkle.style.background = 'white';
            sparkle.style.borderRadius = '50%';
            sparkle.style.pointerEvents = 'none';
            sparkle.style.zIndex = '1000';
            sparkle.style.left = Math.random() * window.innerWidth + 'px';
            sparkle.style.top = Math.random() * window.innerHeight + 'px';
            sparkle.style.opacity = '0';
            sparkle.style.animation = 'sparkle 2s linear forwards';
            
            document.body.appendChild(sparkle);
            
            setTimeout(() => sparkle.remove(), 2000);
        }

        // Add sparkle animation CSS
        const style = document.createElement('style');
        style.textContent = `
            @keyframes sparkle {
                0% { opacity: 0; transform: scale(0) rotate(0deg); }
                50% { opacity: 1; transform: scale(1) rotate(180deg); }
                100% { opacity: 0; transform: scale(0) rotate(360deg); }
            }
        `;
        document.head.appendChild(style);

        // Create sparkles periodically (only on gallery page)
        if (!currentFile) {
            setInterval(createSparkle, 3000);
        }

        // Lazy loading for images
        if ('IntersectionObserver' in window) {
            const imageObserver = new IntersectionObserver((entries, observer) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        const img = entry.target;
                        if (img.dataset.src) {
                            img.src = img.dataset.src;
                            img.classList.remove('lazy');
                            imageObserver.unobserve(img);
                        }
                    }
                });
            });

            // Observe all lazy images
            document.querySelectorAll('img[data-src]').forEach(img => {
                imageObserver.observe(img);
            });
        }

        // Performance optimization: Smooth scrolling
        let isScrolling = false;
        window.addEventListener('scroll', () => {
            if (!isScrolling) {
                window.requestAnimationFrame(() => {
                    // Add any scroll-based animations here
                    isScrolling = false;
                });
                isScrolling = true;
            }
        });

        // Auto-refresh gallery every 30 seconds (only if on gallery page)
        if (!currentFile) {
            setInterval(() => {
                loadGallery();
            }, 30000);
        }

        // Service worker registration for offline support (optional)
        if ('serviceWorker' in navigator) {
            window.addEventListener('load', () => {
                // You can add a service worker here for offline functionality
                console.log('🚀 BensFile loaded successfully!');
            });
        }

        console.log('🚀 BensFile initialized successfully!');
        console.log('Features: Upload, Share, Preview, Auto-expire, Mobile-ready');
        
        // Debug info (remove in production)
        if (currentFile) {
            console.log('Current file:', currentFile);
        }
        
    </script>
</body>
</html>
