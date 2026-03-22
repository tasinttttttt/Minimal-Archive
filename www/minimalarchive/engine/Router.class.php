<?php
class Router
{
    public function __construct(
        private array $routes = [],
        private string $rootUrl = ROOT_URL,
    ) {
        $this->start();
    }

    /**
     * Starts routing
     * @return void
     */
    public function start()
    {
        // Grabs the URI and breaks it apart in case we have querystring stuff
        if (!isset($_SERVER['REQUEST_URI'])) {
            $_SERVER['REQUEST_URI'] = '/';
        }
        $request_uri = explode('?', trim($_SERVER['REQUEST_URI'], '/'), 2);
        $base = $request_uri[0];
        if ($this->rootUrl) {
            $tmp = strstr($request_uri[0], $this->rootUrl);
            $base = substr($tmp, strlen($this->rootUrl) + 1);
        }

        $i = -1;
        while (++$i < count($this->routes)) {
            if (preg_match($this->routes[$i]['match'], $base)) {
                if ($this->routes[$i]['script']) {
                    http_response_code(200);
                    require $this->routes[$i]['script'];
                    exit();
                }
            }
        }
        http_response_code(404);
        exit();
    }
}
