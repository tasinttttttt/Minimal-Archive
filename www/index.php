<?php

$extensions = array("bmp", "webp", "jpg", "jpeg", "png", "gif", "css", "js", "sqlite", "eot", "svg", "otf", "ttf", "woff", "woff2", "avif");

$path = parse_url($_SERVER["REQUEST_URI"], PHP_URL_PATH);
$ext = pathinfo($path, PATHINFO_EXTENSION);

if (in_array(strtolower($ext), $extensions)) {
    // let the server handle the request as-is
    return false;
} else {
    include_once "minimalarchive" . DIRECTORY_SEPARATOR . "engine" . DIRECTORY_SEPARATOR . "bootstrap.php";
    return true;
}
