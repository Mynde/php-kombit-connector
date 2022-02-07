<?php

include_once dirname(__FILE__) . '/http.php';
include_once dirname(__FILE__) . '/wstrust.php';

$config = include('config.php');

// Entity ID
$appliesTo = 'http://stoettesystemerne.dk/service/organisation/3'; // Entity-ID for Organisation (SF1500)

// CVR
$cvr = '11111111'; // Korsbæk Kommune (imaginary test organisation)

// Endpoint
$endpoint = 'https://adgangsstyring.eksterntest-stoettesystemerne.dk/runtime/services/kombittrust/14/certificatemixed';

// Issuer
$issuer = 'https://adgangsstyring.eksterntest-stoettesystemerne.dk/';

// Opening the p12 Certificate

$cert_store = file_get_contents($config['cert_file']);
openssl_pkcs12_read($cert_store, $cert_info, $config['cert_password']);
$cert_key = trim(str_replace("-----END CERTIFICATE-----","",str_replace("-----BEGIN CERTIFICATE-----","",$cert_info['cert'])));
$private = openssl_pkey_get_private($cert_info['pkey']);

// Buidling reqeust (body and header) - body first, so header kan sign it. 
$body = WSTRUST::getRST($appliesTo, $cvr, $issuer, $cert_key);
$header = WSTRUST::getRSTHeader($endpoint, $cert_key);

$request = <<<XML
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
    $header
    $body
</soap:Envelope>
XML;

$request_signed = WSTRUST::getRSTSigned($request, $private);

$result = HTTP::doSOAP($endpoint, $request_signed);

/**
 * Currently not processed further, so code below exit do not work and hasn't been tested!
 */

// parse the RSTR that is returned
//list($dom, $xpath, $token, $proofKey) = WSTRUST::parseRSTR($result);

// get the (possibyly encrypted) token from the response
//list($dom, $token) = WSTRUST::getDecrypted($dom, $xpath, $token, $tokenTypeIPSTS, 'KOMBIT AS - KOMBIT_STS_Admin_Demo.pem');

//if ($token != NULL) {
//	print "\n # (decrypted) security token: #\n\n";
//	print $dom->saveXML($token);
//}

?>