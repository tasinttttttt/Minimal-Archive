<?php
if (!defined('minimalarchive')) {
    redirect('/');
}

/**
 * Detects if a needle exists in an array by key
 */
function array_key_exists_in_array_of_arrays(string|int $needle, ?string $key, ?array $haystack): bool
{
    if (!$needle || !$key || !$haystack || !count($haystack)) {
        return false;
    }
    foreach ($haystack as $item) {
        if (array_key_exists($key, $item) && $needle === $item[$key]) {
            return true;
        }
    }
    return false;
}

/**
 * Redirects to absolute or relative url
 */
function redirect(string $url): never
{
    if (isAbsoluteUrl($url)) {
        header('location: ' . $url);
    } else {
        header('location: ' . url($url));
    }
    exit();
}

/**
 * Detects absolute url
 */
function isAbsoluteUrl(string $url): bool
{
    $pattern = "/^(?:ftp|https?|feed)?:?\/\/(?:(?:(?:[\w\.\-\+!$&'\(\)*\+,;=]|%[0-9a-f]{2})+:)*
    (?:[\w\.\-\+%!$&'\(\)*\+,;=]|%[0-9a-f]{2})+@)?(?:
    (?:[a-z0-9\-\.]|%[0-9a-f]{2})+|(?:\[(?:[0-9a-f]{0,4}:)*(?:[0-9a-f]{0,4})\]))(?::[0-9]+)?(?:[\/|\?]
    (?:[\w#!:\.\?\+\|=&@$'~*,;\/\(\)\[\]\-]|%[0-9a-f]{2})*)?$/xi";

    return (bool) preg_match($pattern, $url);
}

/**
 * Gets file lines into an array
 */
function file_to_lines(string $file): array
{
    $result = [];
    if (file_exists($file)) {
        return explode("\n", file_get_contents($file));
    }
    return $result;
}

/**
 * Turns a textfile into an associative array given a separator
 */
function textFileToArray(string $file, string $separator = ':'): array
{
    $result = [];
    $lines = file_to_lines($file);
    if (is_array($lines) && count($lines)) {
        $i = -1;
        while (++$i < count($lines)) {
            $tokens = explode($separator, trim(htmlspecialchars($lines[$i])), 2);
            if (is_array($tokens) && count($tokens) === 2) {
                $result[trim($tokens[0])] = trim($tokens[1]);
            }
        }
    }
    return $result;
}

/**
 * Returns list of filenames in folder, provided an array of extensions
 */
function getFilenamesInFolder(?string $folder, array $supported_extensions = []): array
{
    if (!$folder || !is_dir($folder)) {
        throw new Exception('no_folder');
    }
    if (!is_array($supported_extensions)) {
        throw new Exception('no_supported_files_provided');
    }
    $result = [];
    $files = scandir($folder);
    $i = -1;
    while (++$i < count($files)) {
        if ($files[$i] != "." && $files[$i] != "..") {
            $extension = strtolower(pathinfo($files[$i], PATHINFO_EXTENSION));
            if (in_array($extension, $supported_extensions)) {
                $result[] = htmlspecialchars($files[$i]);
            }
        }
    }
    return $result;
}

/**
 * Returns a font array object
 * @param  string $name   filename without extension
 * @param  string $folder folder to look fonts for
 * @return array | null
 */
function getFontByName($name, $folder = 'assets/fonts')
{
    try {
        $fonts = getFontsInFolder($folder);
        $i = -1;
        while (++$i < count($fonts)) {
            if ($fonts[$i]['name'] === $name) {
                return $fonts[$i];
            }
        }
        return null;
    } catch (Exception $e) {
        throw $e;
    }
}

/**
 * Returns all fonts in folder
 * @param  string|null $folder folder to look fonts for
 * @return array
 */
function getFontsInFolder(?string $folder = null)
{
    $supported_formats = array(
        'otf' => 'opentype',
        'woff' => 'woff',
        'woff2' => 'woff2',
        'ttf' => 'truetype'
    );
    try {
        $files = getFilenamesInFolder(ROOT_FOLDER . DS . $folder, array_keys($supported_formats));
        $fonts = [];
        foreach ($files as $file) {
            $basename = basename($file);
            $extension = pathinfo($basename, PATHINFO_EXTENSION);
            $name = pathinfo($basename, PATHINFO_FILENAME);
            $fonts[] = array(
                "name" => $name,
                "type" => $supported_formats[$extension],
                "filename" => $basename,
                "path" => url($folder . DS . $file)
            );
        }
        return $fonts;
    } catch (Exception $e) {
        throw $e;
    }
}

/**
 * Return font stylesheet without style tags
 * @param  array  $fonts formatted font array, provided by getFontsInFolder
 * @return string
 */
function getFontsStylesheet(array $fonts)
{
    $i = -1;
    $style = "";
    while (++$i < count($fonts)) {
        $style .= getFontStyle($fonts[$i]);
    }
    return $style;
}

/**
 * Return font face string
 * @param  array $font
 * @return string
 */
function getFontStyle(?array $font = null)
{
    if ($font && is_array($font)) {
        return "@font-face { font-family: '" . $font['name'] . "'; src: url('" . $font['path'] . "') format('" . $font['type'] . "')\n" . strtolower($font['name']) . "{font-family: '" . $font['name'] . "'\n";
    }
    return '';
}

/**
 * Returns an array of images in folder
 * @param  string|null $folder
 * @return array
 */
function getImagesInFolder(?string $folder = null)
{
    $supported_formats = array(
        'gif',
        'jpg',
        'jpeg',
        'png',
        'avif',
        'webp'
    );
    try {
        return getFilenamesInFolder($folder, $supported_formats);
    } catch (Exception $e) {
        throw $e;
    }
}

/**
 * Checks if folder is writable
 * @param  string $folder
 * @return boolean         [description]
 * @throws Exception       "no_rights" if not writable
 */
function folder_is_writable(string $folder)
{
    if (file_exists($folder)) {
        if (!is_writable($folder)) {
            throw new Exception("no_rights", 1);
        } else {
            return true;
        }
    }
    return false;
}

/**
 * Throws exceptions, used to check uploads
 * @param  array  $file
 * @param  string  $uploadfolder
 * @param  integer $max_filesize
 * @return [type]                [description]
 * @throws Exception
 */
function check_uploadedfile($file, $max_filesize = 2097152)
{
    if ($file && is_array($file) && array_key_exists('tmp_name', $file)) {
        if (!is_uploaded_file($file['tmp_name'])) {
            throw new Exception("file_upload_error", 1);
        }
        if (filesize($file['tmp_name']) > $max_filesize) {
            throw new Exception("file_too_large", 1);
        }
    } else {
        throw new Exception("no_file", 1);
    }
}

/**
 * Saves a file, non destructive, finds a name if filename exists
 * @param  array $file
 * @param  string $name   desired filename
 * @param  string $folder destination folder
 * @param  boolean $overwrite
 * @return string         saved file name
 */
function save_file(array $file, ?string $name, string $folder = VAR_FOLDER, bool $overwrite = false): string
{
    if (!$file) {
        return '';
    }

    $filename = $name ?: $file['name'];
    if (!$file["tmp_name"] || !$file["type"]) {
        throw new Exception("bad_file", 1);
    }
    $basename = basename($filename);
    $extension = pathinfo($basename, PATHINFO_EXTENSION);
    $name = pathinfo($basename, PATHINFO_FILENAME);
    if ($overwrite) {
        $correctFilename = $filename;
    } else {
        $correctFilename = "";
        if (file_exists($folder . DS . $basename)) {
            $correctFilename = sanitize_filename($name) . '_' . bin2hex(random_bytes(4)) . '.' . $extension;
        } else {
            $correctFilename = sanitize_filename(basename($filename));
        }
    }
    if (!move_uploaded_file($file['tmp_name'], $folder . DS . $correctFilename)) {
        throw new Exception("file_upload_error", 1);
    }
    return $correctFilename;
}

/**
 * Renames a file
 * @param  string $file    file src
 * @param  string $newname desired name
 * @return string          saved filename or input if no file was found
 */
function update_filename(?string $file, ?string $newname): string
{
    if (!$file || !$newname) {
        return $file;
    }
    $dir = pathinfo($file, PATHINFO_DIRNAME);
    $ext = pathinfo($file, PATHINFO_EXTENSION);
    $filename = pathinfo($file, PATHINFO_FILENAME);
    $sanitizedNewname = $dir . DS . sanitize_filename($newname) . '.' . $ext;
    if ($newname !== $filename) {
        if (file_exists($file)) {
            while (file_exists($sanitizedNewname)) {
                $sanitizedNewname = $dir . DS . sanitize_filename() . '.' . $ext;
            }
            rename($file, $sanitizedNewname);
            return $sanitizedNewname;
        }
    }
    return $file;
}

/**
 * Puts the content of an associative array into a file
 * @param  array  $data associative array
 * @param  string $file destination
 * @return bool
 * @throws Exception    if write fails
 */
function array_to_file(array $data, $file = DEFAULT_METAFILE)
{
    try {
        if (!$data || !is_array($data) || !count($data)) {
            return true;
        }
        $dir = ROOT_FOLDER;
        $filename = $file;
        if (!file_exists($dir)) {
            mkdir($dir, 0755, true);
        }
        $file = fopen($filename, "w");
        foreach ($data as $key => $value) {
            fwrite($file, (string) $key . ": " . (string) $value . "\n");
        }
        fclose($file);
        return true;
    } catch (Exception $e) {
        throw new Exception($e->getMessage(), $e->getCode());
    }
}


function get_secret_from_file($file = DEFAULT_CONFIGFILE)
{
    $data = textFileToArray($file);
    if (array_key_exists('SECRET', $data)) {
        return $data['SECRET'];
    }
    return '';
}

function get_host()
{
    $possibleHostSources = array('HTTP_X_FORWARDED_HOST', 'HTTP_HOST', 'SERVER_NAME', 'SERVER_ADDR');
    $sourceTransformations = array(
        "HTTP_X_FORWARDED_HOST" => function ($value) {
            $elements = explode(',', $value);
            return trim(end($elements));
        }
    );
    $host = '';
    foreach ($possibleHostSources as $source) {
        if (!empty($host)) {
            break;
        }
        if (!isset($_SERVER[$source]) || empty($_SERVER[$source])) {
            continue;
        }
        $host = $_SERVER[$source];
        if (array_key_exists($source, $sourceTransformations)) {
            $host = $sourceTransformations[$source]($host);
        }
    }

    // Remove port number from host
    $host = preg_replace('/:\d+$/', '', $host);

    return trim($host);
}

function get_header_auth_token()
{
    if (array_key_exists('HTTP_AUTHORIZATION', $_SERVER)) {
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'];
        $arr = explode(" ", $authHeader);
        return count($arr) >= 2 ? $arr[1] : '';
    }
    return '';
}

/**
 * Returns array of credentials from two lined text file
 * @param  string $file filename
 * @return array       containing email and password
 */
function get_credentials_from_file($file = DEFAULT_ACCOUNTFILE): array
{
    $credentials = array(
        'email' => null,
        'password' => null
    );
    $lines = file_to_lines($file);
    if ($lines && count($lines) >= 2) {
        $credentials['email'] = $lines[0];
        $credentials['password'] = $lines[1];
    }
    return $credentials;
}

/**
 * Verifies credentials
 * @param  string $email
 * @param  string $password
 * @return bool
 */
function check_credentials(string $email, string $password)
{
    if (!has_account() || !$email || !$password) {
        return false;
    }
    $credentials = get_credentials_from_file();
    return password_verify(sanitize_email($email), $credentials['email']) && password_verify($password, $credentials['password']);
}

/**
 * Checks whether password string passes certain criteria
 * @param  mixed $password
 * @return boolean
 */
function check_password($password)
{
    if (mb_strlen($password) < 8) {
        throw new Exception("password_short.", 1);
    }

    if (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9]).{8,}$/', $password)) {
        throw new Exception("password_bad", 1);
    }

    return true;
}

function get_token(string $form_name, string $filename = '.token'): string
{
    $file = VAR_FOLDER . DS . $filename;
    if (file_exists($file)) {
        $lines = explode("\n", file_get_contents($file));
        if (is_array($lines) && count($lines)) {
            return hash('sha512', $lines[0] . session_id() . $form_name);
        }
    }

    return '';
}

/**
 * Compares provided token with token on file
 */
function check_token(?string $token, ?string $form_name): bool
{
    if (!$token) {
        return false;
    }
    return $token === get_token($form_name);
}

/**
 * Generate token and save it on file
 */
function create_token(string $filename = '.token'): bool
{
    try {
        if (!file_exists(VAR_FOLDER)) {
            mkdir(VAR_FOLDER, 0755, true);
        }
        $file = fopen(VAR_FOLDER . DS . $filename, "w");
        fwrite($file, bin2hex(random_bytes(32)) . "\n");
        fclose($file);
        return true;
    } catch (Exception $e) {
        throw new Exception($e->getMessage(), $e->getCode());
    }
    return false;
}

/**
 * Parses sessions file content
 */
function parse_sessions(string $content): array
{
    try {
        $json = json_decode($content);
        if ($json && count($json)) {
            return $json;
        }
    } catch (\Exception $e) {
        throw $e;
    }
    return [];
}

/**
 * Invalidates session on file
 */
function invalidate_sessions(string $filename = DEFAULT_SESSIONSFILE): bool
{
    session_destroy();
    if (!file_exists(VAR_FOLDER) || !file_exists($filename)) {
        return true;
    }
    if (file_exists($filename)) {
        unlink($filename);
        return true;
    }
    return false;
}

/**
 * Validates session on file
 */
function validate_session(string $id, string $key): bool
{
    if (file_exists(DEFAULT_SESSIONSFILE)) {
        $content = file_get_contents(DEFAULT_SESSIONSFILE);
        $sessions = parse_sessions($content);
        if (($index = getindex_sessionbykey($id, $key, $sessions)) > -1) {
            if (!isset($sessions[$index])) {
                return false;
            }
            if (((int) (new \DateTime())->getTimestamp() - (int) $sessions[$index]->time) / (60 * 60) < SESSION_MAXDURATION) {
                return true;
            }
        }
    }
    return false;
}

/**
 * Returns session index provided a valid id/key pair
 * @param  mixed $id
 * @param  mixed $key
 * @param  array $sessions
 * @return int  > 0 if valid, -1 if not
 */
function getindex_sessionbykey($id, $key, $sessions)
{
    if (!$sessions) {
        return -1;
    }
    $i = -1;
    while (++$i < count($sessions)) {
        if (property_exists($sessions[$i], $key)) {
            if (password_verify($id, $sessions[$i]->$key)) {
                return $i;
            }
        }
    }
    return $i;
}

/**
 * Append new session to file
 * @param mixed $id
 * @param mixed $key
 */
function add_session($id, $key)
{
    try {
        $dir = VAR_FOLDER;
        $filename = DEFAULT_SESSIONSFILE;
        if (!file_exists($dir)) {
            mkdir($dir, 0755, true);
        }
        $sessions = get_sessions();
        if (($index = getindex_sessionbykey($id, $key, $sessions)) > -1 && isset($sessions[$index])) {
            $sessions[$index]->time = (new \DateTime())->getTimestamp();
        } else {
            $sessions[] = (object) array(
                'id' => password_hash($id, PASSWORD_DEFAULT),
                'time' => (new \DateTime())->getTimestamp()
            );
        }
        $file = fopen($filename, "w");
        fwrite($file, json_encode($sessions) . "\n");
        fclose($file);
        return true;
    } catch (Exception $e) {
        throw new Exception($e->getMessage(), $e->getCode());
    }
}

function get_sessions(): array
{
    if (!file_exists(VAR_FOLDER)) {
        mkdir(VAR_FOLDER, 0755, true);
    }
    if (file_exists(DEFAULT_SESSIONSFILE)) {
        return parse_sessions(file_get_contents(DEFAULT_SESSIONSFILE));
    } else {
        return [];
    }
}

/**
 * Deletes everything in the var folder except defaults
 * @return void
 */
function clean_installation()
{
    $files = glob(VAR_FOLDER . DS . '*');
    foreach ($files as $file) {
        if (is_file($file) && $file !== DEFAULT_ACCOUNTFILE && $file !== DEFAULT_METAFILE) {
            unlink($file);
        }
    }
}

/**
 * Delete metafiles, var folder content, with an option to delete images
 * @param  boolean $deleteimages
 * @return void
 */
function uninstall(bool $deleteimages = false)
{
    $meta = file_exists(DEFAULT_METAFILE) ? textFileToArray(DEFAULT_METAFILE) : null;
    $files = glob(VAR_FOLDER . DS . '{,.}[!.,!..]*', GLOB_MARK | GLOB_BRACE);
    foreach ($files as $file) {
        unlink($file);
    }

    if (true === $deleteimages) {
        $imagesdir = $meta && count($meta) && array_key_exists('imagesfolder', $meta) ? ROOT_FOLDER . DS . $meta['imagesfolder'] : DEFAULT_IMAGEFOLDER;

        $files = glob($imagesdir . DS . '{,.}[!.,!..]*', GLOB_MARK | GLOB_BRACE);
        foreach ($files as $file) {
            unlink($file);
        }
    }

    if ($meta) {
        unlink(DEFAULT_METAFILE);
    }
}

/**
 * Output a stylized error html
 */
function put_error(string $message)
{
    echo "<aside class=\"notice error\">" . htmlspecialchars($message) . "</aside>";
}

/**
 * Output a stylized success html
 */
function put_success(string $message): void
{
    echo "<aside class=\"notice success\">" . htmlspecialchars($message) . "</aside>";
}

/**
 * Applies sanitization rules to filename string
 */
function sanitize_filename(?string $filename = null, ?string $replace = '-'): string
{
    if (!$filename) {
        return bin2hex(random_bytes(4));
    }

    // Remove control characters and null bytes
    $filename = preg_replace('/[\x00-\x1f\x7f]/u', '', $filename);

    // Replace sequences of reserved characters and shell metacharacters with a single hyphen
    $filename = preg_replace('/[<>:"\/\\\\|?*&$#()\[\]{}\'!~;]+/', '-', $filename);

    // Remove leading/trailing periods, spaces, and hyphens
    $filename = trim($filename, ' .-');

    // Handle Windows reserved device names
    $reserved_names = [
        'CON',
        'PRN',
        'AUX',
        'NUL',
        'COM1',
        'COM2',
        'COM3',
        'COM4',
        'COM5',
        'COM6',
        'COM7',
        'COM8',
        'COM9',
        'LPT1',
        'LPT2',
        'LPT3',
        'LPT4',
        'LPT5',
        'LPT6',
        'LPT7',
        'LPT8',
        'LPT9'
    ];

    if (in_array(strtoupper($filename), $reserved_names)) {
        $filename = '_' . $filename;
    }

    // Limit filename to 255 characters
    return substr($filename, 0, 255);
}

/**
 * Apply sanitization rules to email string
 */
function sanitize_email(string $text): string
{
    return filter_var(strtolower(trim($text)), FILTER_SANITIZE_EMAIL);
}

/**
 * Apply sanitization rules to password string
 */
function sanitize_password(?string $text): string
{
    return $text;
}

/**
 * Apply sanitization rules to text string
 */
function sanitize_text(?string $text = ''): string
{
    return htmlspecialchars($text);
}

/**
 * Test if default account file exists
 */
function has_account(): bool
{
    return file_exists(DEFAULT_ACCOUNTFILE);
}

/**
 * Test if default metafile file exists and contains data
 */
function has_meta(): bool
{
    return file_exists(DEFAULT_METAFILE) && ($meta = textFileToArray(DEFAULT_METAFILE)) && count($meta);
}

/**
 * Test if installation files exist
 */
function is_installed(): bool
{
    return has_account() && has_meta();
}

/**
 * Perform stranslation on given string
 * @param  mixed $string
 * @param  string $extra    extra content to append to translation
 * @return string
 */
function translate(?string $string, ?string $extra = "", ?string $language = ''): string
{
    $httpLang = array_key_exists('HTTP_ACCEPT_LANGUAGE', $_SERVER) ? mb_substr($_SERVER['HTTP_ACCEPT_LANGUAGE'], 0, 2) : null;
    $translation = loadTranslation(!$language ? $httpLang : $language);
    if ($translation && count($translation)) {
        $translated = '';
        if (array_key_exists($string, $translation)) {
            $translated = $translation[$string];
            $translated .= mb_strlen($extra) ? "<br/>" . $extra : "";
        } else {
            return $translated = $language != "en" ? translate($string, $extra, 'en') : '';
        }
        return $translated;
    } else {
        return '';
    }
}

/**
 * Load translation from file
 * @param  string $language
 * @return array
 */
function loadTranslation(?string $language = 'en'): array
{
    $fileContent = @file_get_contents(TRANSLATIONS_FOLDER . DS . $language . '.json');
    if ($fileContent) {
        $content = json_decode($fileContent, true);
        if ($content && count($content)) {
            return $content;
        }
    }
    return $language == 'en' ? [] : loadTranslation('en');
}

/**
 * Build absolute url from provided path
 * @param  string $path
 * @return string
 */
function url(?string $path = ''): string
{
    // server protocol
    $protocol = !isset($_SERVER['HTTPS']) ? 'http' : 'https';

    // domain name
    $domain = $_SERVER['SERVER_NAME'] ?? 'localhost';

    // server port
    $port = $_SERVER['SERVER_PORT'] ?? 80;
    $disp_port = ($protocol == 'http' && $port == 80 || $protocol == 'https' && $port == 443) ? '' : ":$port";

    $host = "$protocol://$domain$disp_port";
    $root = !ROOT_URL ? '' : DS . ROOT_URL;
    $path = ($path && $path[0] !== '/' ? '/' : '') . ($path ? htmlspecialchars($path) : '');
    // put em all together to get the complete base URL
    return "$host$root$path";
}

/**
 * Output json formatted response with http response code
 * @param  string  $message
 * @param  integer $code    html code, defaults to server error
 * @param  mixed  $data     content
 * @return void
 */
function json_response(?string $message = 'Error', ?int $code = 500, mixed $data = null): void
{
    header('Content-Type: application/json');
    $response = [
        'code' => $code,
        'data' => $data,
        'message' => $message
    ];
    http_response_code($code);
    echo json_encode($response);
}

function login()
{
    if (isset($_POST['email']) && isset($_POST['password']) && check_token($_POST['csrf_token'], 'edit')) {
        if (check_credentials($_POST['email'], $_POST['password']) === true) {
            // if credentials are OK, setup session and create session file
            $_SESSION['id'] = $_POST['email'];
            add_session($_POST['email'], 'id');
            return true;
        } else {
            throw new \Exception('bad credentials');
        }
    }
    return false;
}
