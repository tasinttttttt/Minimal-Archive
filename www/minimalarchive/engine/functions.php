<?php
if (!defined('minimalarchive')) {
    redirect('/');
}

/**
 * Detects if a needle exists in an array by key
 * @param  any     $needle   what to find
 * @param  string     $key      array key to check
 * @param  array|null $haystack array of arrays to search
 * @return bool
 */
function array_key_exists_in_array_of_arrays($needle, string $key, array $haystack = null)
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
 * @param  string $url
 * @return [type]      [description]
 */
function redirect($url)
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
 * @param  string  $url
 * @return boolean      [description]
 */
function isAbsoluteUrl($url)
{
    $pattern = "/^(?:ftp|https?|feed)?:?\/\/(?:(?:(?:[\w\.\-\+!$&'\(\)*\+,;=]|%[0-9a-f]{2})+:)*
    (?:[\w\.\-\+%!$&'\(\)*\+,;=]|%[0-9a-f]{2})+@)?(?:
    (?:[a-z0-9\-\.]|%[0-9a-f]{2})+|(?:\[(?:[0-9a-f]{0,4}:)*(?:[0-9a-f]{0,4})\]))(?::[0-9]+)?(?:[\/|\?]
    (?:[\w#!:\.\?\+\|=&@$'~*,;\/\(\)\[\]\-]|%[0-9a-f]{2})*)?$/xi";

    return (bool) preg_match($pattern, $url);
}

/**
 * Gets file lines into an array
 * @param  string $file filename
 * @return array       [description]
 */
function file_to_lines(string $file)
{
    $result = array();
    if (file_exists($file)) {
        return explode("\n", file_get_contents($file));
    }
    return $result;
}

/**
 * Turns a textfile into an associative array given a separator
 * @param  string $file         filename
 * @param  string $separator
 * @return array                can be empty
 */
function textFileToArray(string $file, string $separator = ':')
{
    $result = array();
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
 * @param  string|null $folder    folder to scan
 * @param  array       $supported array of extensions
 * @return array                  can be an empty array
 */
function getFilenamesInFolder(string $folder = null, array $supported = [])
{
    if (!$folder || !is_dir($folder)) {
        throw new Exception('no_folder');
        return array();
    }
    if (!is_array($supported)) {
        throw new Exception('no_supported_files_provided');
        return array();
    }
    $result = array();
    $files = scandir($folder);
    $i = -1;
    while (++$i < count($files)) {
        if ($files[$i] != "." && $files[$i] != "..") {
            $extension = strtolower(pathinfo($files[$i], PATHINFO_EXTENSION));
            if (in_array($extension, $supported)) {
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
function getFontsInFolder(string $folder = null)
{
    $supported_formats = array(
        'otf' => 'opentype',
        'woff' => 'woff',
        'woff2' => 'woff2',
        'ttf' => 'truetype'
    );
    try {
        $files = getFilenamesInFolder(ROOT_FOLDER . DS . $folder, array_keys($supported_formats));
        $fonts = array();
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
function getFontStyle(array $font = null)
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
function getImagesInFolder(string $folder = null)
{
    $supported_formats = array(
        'gif',
        'jpg',
        'jpeg',
        'png'
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
function check_uploadedfile($file, $uploadfolder = VAR_FOLDER, $max_filesize = 2097152)
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
function save_file($file, $name = null, $folder = VAR_FOLDER, $overwrite = false)
{
    if ($file) {
        $filename = $name ? $name : $file['name'];
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
            if (file_exists($folder . DS. $basename)) {
                $correctFilename = sanitize_filename($name) . '_' . bin2hex(random_bytes(4)) . '.' . $extension;
            } else {
                $correctFilename = sanitize_filename(basename($filename));
            }
        }
        if (!move_uploaded_file($file['tmp_name'], $folder . DS. $correctFilename)) {
            throw new Exception("file_upload_error", 1);
        }
        return $correctFilename;
    }
}

/**
 * Renames a file
 * @param  string $file    file src
 * @param  string $newname desired name
 * @return string          saved filename or input if no file was found
 */
function update_filename($file = null, $newname = null)
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

/**
 * Returns array of credentials from two lined text file
 * @param  string $file filename
 * @return array       containing email and password
 */
function get_credentials_from_file($file = VAR_FOLDER . DS . '.account')
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
    return password_verify(sanitize_email($email), $credentials['email']) && password_verify(sanitize_password($password), $credentials['password']);
}

/**
 * Checks whether password string passes certain criteria
 * @param  mixed $password
 * @return boolean
 */
function check_password($password)
{
    if (strlen($password) < 8) {
        throw new Exception("password_short.", 1);
        return false;
    }
    if (!preg_match("/[0-9]{1,}/", $password) || !preg_match("/[A-Z]{1,}/", $password)) {
        throw new Exception("password_bad", 1);
        return false;
    }
    return true;
}

function get_token($form_name, $filename = '.token')
{
    $file = VAR_FOLDER . DS . $filename;
    if (file_exists($file)) {
        $lines = explode("\n", file_get_contents($file));
        if (is_array($lines) && count($lines)) {
            return hash('sha512', $lines[0] . session_id() . $form_name);
        }
    }
    return false;
}

/**
 * Compares provided token with token on file
 * @param  string $token
 * @param  string $form_name
 * @return boolean
 */
function check_token($token, $form_name)
{
    if (is_bool($token)) {
        return false;
    }
    return $token === get_token($form_name);
}

/**
 * Generate token and save it on file
 * @param  string $filename
 * @return void
 * @throws Exception
 */
function create_token($filename = '.token')
{
    try {
        $dir = VAR_FOLDER . DS;
        if (!file_exists($dir)) {
            mkdir($dir, 0755, true);
        }
        $file = fopen($dir . DS . $filename, "w");
        fwrite($file, bin2hex(random_bytes(32)) . "\n");
        fclose($file);
    } catch (Exception $e) {
        throw new Exception($e->getMessage(), $e->getCode());
    }
}

/**
 * Parses sessions file content
 * @param  mixed $content json string, anything would return an empty array
 * @return array
 */
function parse_sessions($content)
{
    if (!$content || !is_string($content)) {
        return [];
    }
    $json = json_decode($content);
    if ($json && count($json)) {
        return $json;
    }
    return [];
}

/**
 * Invalidates session on file
 * @param  mixed $id  session id
 * @param  mixed $key session id key
 * @return void
 */
function invalidate_session($id, $key)
{
    session_destroy();
    $dir = VAR_FOLDER;
    $filename = DEFAULT_SESSIONSFILE;
    if (!file_exists($dir)) {
        return false;
    }
    $sessions = array();
    if (file_exists($filename)) {
        $content = file_get_contents($filename);
        $sessions = parse_sessions($content);
        if (($index = getindex_sessionbykey($id, $key, $sessions)) > -1) {
            $i = 0;
            foreach ($sessions as $session) {
                if ($i !== $index) {
                    $sessions[$i] = $session;
                }
                $i++;
            }
        }
        $file = fopen($filename, "w");
        fwrite($file, json_encode($sessions). "\n");
        fclose($file);
    }
}

/**
 * Validates session on file
 * @param  mixed $id  session id
 * @param  mixed $key session key
 * @return boolean
 */
function validate_session($id, $key)
{
    $dir = VAR_FOLDER;
    $filename = DEFAULT_SESSIONSFILE;
    if (!file_exists($dir)) {
        return false;
    }
    if (file_exists($filename)) {
        $content = file_get_contents($filename);
        $sessions = parse_sessions($content);
        if (($index = getindex_sessionbykey($id, $key, $sessions)) > -1) {
            if (((int)(new \DateTime())->getTimestamp() - (int)$sessions[$index]->time) / (60 * 60) < SESSION_MAXDURATION) {
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
        $sessions = array();
        $account = null;
        // if file exists, try to update the entry
        if (file_exists($filename)) {
            $content = file_get_contents($filename);
            $sessions = parse_sessions($content);
            if (($index = getindex_sessionbykey($id, $key, $sessions)) > -1) {
                $sessions[$index]->time = (new \DateTime())->getTimestamp();
            }
        }
        // else, create a new session
        if (!$account) {
            $sessions[] = (object) array(
                'id' => password_hash($id, PASSWORD_DEFAULT),
                'time' => (new \DateTime())->getTimestamp()
            );
        }
        $file = fopen($filename, "w");
        fwrite($file, json_encode($sessions). "\n");
        fclose($file);
        return true;
    } catch (Exception $e) {
        throw new Exception($e->getMessage(), $e->getCode());
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
        if (is_file($file) && $file !== DEFAULT_ACCOUNTFILE && $FILE !== DEFAULT_METAFILE) {
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
    $files = glob(VAR_FOLDER . DS . '{,.}[!.,!..]*', GLOB_MARK|GLOB_BRACE);
    foreach ($files as $file) {
        unlink($file);
    }

    if (true === $deleteimages) {
        $imagesdir = $meta && count($meta) && array_key_exists('imagesfolder', $meta) ? ROOT_FOLDER . DS . $meta['imagesfolder'] : DEFAULT_IMAGEFOLDER;

        $files = glob($imagesdir . DS . '{,.}[!.,!..]*', GLOB_MARK|GLOB_BRACE);
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
 * @param  string $message
 * @return void
 */
function put_error(string $message)
{
    echo "<aside class=\"notice error\">${message}</aside>";
}

/**
 * Output a stylized success html
 * @param  string $message
 * @return void
 */
function put_success(string $message)
{
    echo "<aside class=\"notice success\">${message}</aside>";
}

/**
 * Applies sanitization rules to filename string
 * @param  string|null $str
 * @param  string      $replace
 * @return string
 */
function sanitize_filename(string $str = null, string $replace = '-')
{
    if (!$str) {
        return bin2hex(random_bytes(4));
    }
    // Remove unwanted chars
    $str = mb_ereg_replace("([^\w\s\d\-_~,;\[\]\(\).])", $replace, $str);
    // Replace multiple dots by custom char
    $str = mb_ereg_replace("([\.]{2,})", $replace, $str);
    return $str;
}

/**
 * Apply sanitization rules to email string
 * @param  string $text
 * @return string
 */
function sanitize_email(string $text = '')
{
    return filter_var(strtolower(trim($text)), FILTER_SANITIZE_EMAIL);
}

/**
 * Apply sanitization rules to password string
 * @param  string $text
 * @return string
 */
function sanitize_password(string $text = '')
{
    return filter_var($text, FILTER_SANITIZE_STRING);
}

/**
 * Apply sanitization rules to text string
 * @param  string $text
 * @return string
 */
function sanitize_text(string $text = '')
{
    return filter_var(trim($text), FILTER_SANITIZE_FULL_SPECIAL_CHARS);
}

/**
 * Test if default account file exists
 * @return boolean
 */
function has_account()
{
    return file_exists(DEFAULT_ACCOUNTFILE);
}

/**
 * Test if default metafile file exists and contains data
 * @return boolean
 */
function has_meta()
{
    return file_exists(DEFAULT_METAFILE) && ($meta = textFileToArray(DEFAULT_METAFILE)) && count($meta);
}

/**
 * Test if installation files exist
 * @return boolean
 */
function is_installed()
{
    return has_account() && has_meta();
}

/**
 * Perform stranslation on given string
 * @param  mixed $string
 * @param  string $extra    extra content to append to translation
 * @return string
 */
function translate($string, $extra = "", $language = '')
{
    $translation = loadTranslation(!$language ? substr($_SERVER['HTTP_ACCEPT_LANGUAGE'], 0, 2) : $language);
    if ($translation && count($translation)) {
        $translated = '';
        if (array_key_exists($string, $translation)) {
            $translated = $translation[$string];
            $translated .= strlen($extra) ? "<br/>" . $extra : "";
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
function loadTranslation($language = 'en')
{
    $content = json_decode(file_get_contents(TRANSLATIONS_FOLDER . DS . $language . '.json'), true);
    if ($content && count($content)) {
        return $content;
    } else {
        return $language == 'en' ? array() : loadTranslation('en');
    }
}

/**
 * Build absolute url from provided path
 * @param  string $path
 * @return string
 */
function url(string $path = '')
{
    // server protocol
    $protocol = empty($_SERVER['HTTPS']) ? 'http' : 'https';

    // domain name
    $domain = $_SERVER['SERVER_NAME'];

    // server port
    $port = $_SERVER['SERVER_PORT'];
    $disp_port = ($protocol == 'http' && $port == 80 || $protocol == 'https' && $port == 443) ? '' : ":$port";

    // put em all together to get the complete base URL
    return "${protocol}://${domain}${disp_port}" . (!ROOT_URL ? '' : DS . ROOT_URL) . ($path && $path[0] !== '/' ? '/' : '') . ($path ? htmlspecialchars($path) : '');
}

/**
 * Output json formatted response with http response code
 * @param  string  $message
 * @param  integer $code    html code, defaults to server error
 * @param  mixed  $data     content
 * @return void
 */
function json_response($message = 'Error', $code = 500, $data = null)
{
    header('Content-Type: application/json');
    $response = array(
        'code' => $code,
        'data' => $data,
        'message' => $message
    );
    http_response_code($code);
    echo json_encode($response);
}
