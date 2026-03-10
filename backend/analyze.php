<?php
header("Access-Control-Allow-Origin: http://localhost:5173");
header("Content-Type: application/json");
header("Access-Control-Allow-Methods: GET");

// Load .env file
$env = parse_ini_file(__DIR__ . '/.env');
$vtKey = $env['VIRUSTOTAL_API_KEY'];
$abuseKey = $env['ABUSEIPDB_API_KEY'];

// Get and sanitize input
$query = isset($_GET['query']) ? trim($_GET['query']) : '';

if (empty($query)) {
    http_response_code(400);
    echo json_encode(["error" => "No IP or domain provided"]);
    exit;
}

// Detect if IP or domain
$isIP = filter_var($query, FILTER_VALIDATE_IP);

// ---- VirusTotal ----
$vtEncoded = urlencode(base64_encode($query));
$vtUrl = "https://www.virustotal.com/api/v3/" . ($isIP ? "ip_addresses" : "domains") . "/{$vtEncoded}";

// Fix: VirusTotal uses raw base64 without padding for domains/IPs
$vtId = rtrim(base64_encode($query), '=');
$vtUrl = "https://www.virustotal.com/api/v3/" . ($isIP ? "ip_addresses/$query" : "domains/$vtId");

$vtCurl = curl_init($vtUrl);
curl_setopt($vtCurl, CURLOPT_RETURNTRANSFER, true);
curl_setopt($vtCurl, CURLOPT_HTTPHEADER, ["x-apikey: $vtKey"]);
$vtResponse = json_decode(curl_exec($vtCurl), true);
curl_close($vtCurl);

// ---- AbuseIPDB (only works for IPs) ----
$abuseData = null;
if ($isIP) {
    $abuseUrl = "https://api.abuseipdb.com/api/v2/check?ipAddress={$query}&maxAgeInDays=90&verbose";
    $abuseCurl = curl_init($abuseUrl);
    curl_setopt($abuseCurl, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($abuseCurl, CURLOPT_HTTPHEADER, [
        "Key: $abuseKey",
        "Accept: application/json"
    ]);
    $abuseData = json_decode(curl_exec($abuseCurl), true);
    curl_close($abuseCurl);
}

// ---- Build response ----
$stats = $vtResponse['data']['attributes']['last_analysis_stats'] ?? null;
$malicious = $stats['malicious'] ?? 0;
$suspicious = $stats['suspicious'] ?? 0;
$harmless = $stats['harmless'] ?? 0;
$total = $malicious + $suspicious + $harmless;
$score = $total > 0 ? round((($malicious + $suspicious) / $total) * 100) : 0;

$result = [
    "query"      => $query,
    "type"       => $isIP ? "IP Address" : "Domain",
    "score"      => $score,
    "malicious"  => $malicious,
    "suspicious" => $suspicious,
    "harmless"   => $harmless,
    "country"    => $vtResponse['data']['attributes']['country'] ?? "N/A",
    "owner"      => $vtResponse['data']['attributes']['as_owner'] ?? 
                    $vtResponse['data']['attributes']['registrar'] ?? "N/A",
    "categories" => array_values($vtResponse['data']['attributes']['categories'] ?? []),
    "abuse_score"=> $abuseData['data']['abuseConfidenceScore'] ?? null,
    "abuse_reports" => $abuseData['data']['totalReports'] ?? null,
    "isp"        => $abuseData['data']['isp'] ?? null,
];

echo json_encode($result);