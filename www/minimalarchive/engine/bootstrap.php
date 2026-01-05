<?php
require_once 'constants.php';

session_start();

include_once 'functions.php';
include_once 'class_loader.php';

// order matters
new Router(array(
    array(
        "match" => "/(^$|^\b$|\bindex|\bhome|\bhomepage|\bindex\.php|\bindex\.html)\/?$/",
        "script" => BASE_FOLDER . DS . 'index.php'
    ),
    array(
        "match" => "/(\binstall)\/?$/",
        "script" => BASE_FOLDER . DS . 'install.php'
    ),
    array(
        "match" => "/(\buninstall)\/?$/",
        "script" => BASE_FOLDER . DS . 'uninstall.php'
    ),
    array(
        "match" => "/(\bedit)\/?$/",
        "script" => BASE_FOLDER . DS . 'edit.php'
    ),
    array(
        "match" => "/(\bapi)\/?$/",
        "script" => BASE_FOLDER . DS . 'api.php'
    ),
    array(
        "match" => "/./",
        "script" => BASE_FOLDER . DS . '404.php'
    ),
));
