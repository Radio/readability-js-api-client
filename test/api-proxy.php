<?php

if (!function_exists('http_parse_headers')) {
    function http_parse_headers($rawHeaders) {
        $headers = array();
        $key = '';

        foreach(explode("\n", $rawHeaders) as $headerLine) {
            $header = explode(':', $headerLine, 2);
            if (isset($header[1])) {
                if (!isset($headers[$header[0]])) {
                    $headers[$header[0]] = trim($header[1]);
                } elseif (is_array($headers[$header[0]])) {
                    $headers[$header[0]] = array_merge($headers[$header[0]], array(trim($header[1])));
                } else {
                    $headers[$header[0]] = array_merge(array($headers[$header[0]]), array(trim($header[1])));
                }
                $key = $header[0];
            } else {
                if (substr($header[0], 0, 1) == "\t") {
                    $headers[$key] .= "\r\n\t" . trim($header[0]);
                } elseif (!$key) {
                    $headers[0] = trim($header[0]);
                    trim($header[0]);
                }
            }
        }

        return $headers;
    }
}

$connection = curl_init();

$params = $_REQUEST;
$method = $_SERVER['REQUEST_METHOD'];
$apiPath = str_replace($_SERVER['SCRIPT_NAME'], '', $_SERVER['REQUEST_URI']);

$url = 'https://readability.com/api' . $apiPath;
$query = http_build_query($params);
if (in_array($method, ['GET', 'DELETE', 'HEAD'])) {
    //$url .= '?' . $query;
}
curl_setopt($connection, CURLOPT_URL, $url);
curl_setopt($connection, CURLOPT_HEADER, ($method === 'HEAD'));
curl_setopt($connection, CURLOPT_RETURNTRANSFER, true);
curl_setopt($connection, CURLOPT_CUSTOMREQUEST, strtoupper($method));
if ($method === 'POST') {
    curl_setopt($connection, CURLOPT_POSTFIELDS, $query);
    curl_setopt($connection, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);
}

$response = curl_exec($connection);
$httpCode = curl_getinfo($connection, CURLINFO_HTTP_CODE);
if ($method === 'HEAD') {
    $headers = http_parse_headers($response);
    foreach ($headers as $key => $value) {
        if (!in_array($key, ['Date', 'Server'])) {
            header(($key ? $key . ': ' : '') . $value);
        }
    }
} else {
    header('HTTP/1.1 ' . $httpCode . ' OK or NOT OK');
    echo $response;
}

curl_close($connection);

exit;