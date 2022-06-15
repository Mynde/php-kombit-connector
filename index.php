<?php

include_once dirname(__FILE__) . '/http.php';
include_once dirname(__FILE__) . '/kombit-sts.php';
include_once dirname(__FILE__) . '/kombit-services.php';

$config = include('config.php');

// Entity ID (Current is Entity-ID for Organisation (SF1500))
$appliesTo = 'http://stoettesystemerne.dk/service/organisation/3';

// CVR
$cvr = '11111111'; // Korsbæk Kommune (imaginary test organisation)

// Endpoint
$endpoint_sts = 'https://adgangsstyring.eksterntest-stoettesystemerne.dk/runtime/services/kombittrust/14/certificatemixed';
$endpoint_org = 'https://organisation.eksterntest-stoettesystemerne.dk/organisation/bruger/6/';

// Actions
$action_sts = $endpoint_sts;
$action_org = 'http://kombit.dk/sts/organisation/bruger/laes';

// Issuer
$issuer = 'https://adgangsstyring.eksterntest-stoettesystemerne.dk/';

// Opening the p12 Certificate
// TODO: Inkludere dette "udtag" i klaserne... så man bare giver config med pass og filepath
$cert_store = file_get_contents($config['cert_file']);
openssl_pkcs12_read($cert_store, $cert_info, $config['cert_password']);
$cert_key = trim(str_replace("-----END CERTIFICATE-----","",str_replace("-----BEGIN CERTIFICATE-----","",$cert_info['cert'])));
$private = openssl_pkey_get_private($cert_info['pkey']);

// Buidling reqeust (body and header) 
$request_sts = STS::getRST($endpoint_sts, $appliesTo, $cvr, $issuer, $cert_key);

$request_sts_signed = STS::getRSTSigned($request_sts, $private);

$response_sts = HTTP::doSOAP($endpoint_sts, $request_sts_signed);

if(true == false) { 
    echo '<div style="display: block; ">';
    if (strpos($response_sts, 'Fault') !== false) {
        echo '<h2 style="color: red; text-align: center;">Failure (STS)</h2>';
    } else {
        echo '<h2 style="color: green; text-align: center;">Succes (STS)</h2>';        
    }

    echo '<div style="float: left"><label for="textXml1">Request STS:</label><br><textarea id="txtXml0" rows="90" cols="120" readonly="readonly" style="padding: 10px;">'.$request_sts_signed.'</textarea></div>';
    echo '<div style="float: right"><label for="textXml2">Response STS:</label><br><textarea id="txtXml00" rows="90" cols="120" readonly="readonly" style="padding: 10px;">'.$response_sts.'</textarea></div>';
    echo '</div>';
}
//parse the RSTR that is returned
list($dom_sts, $xpath, $token, $proofKey) = STS::parseRSTR($response_sts);

// get the (possibyly encrypted) token from the response
list($dom_sts, $token) = STS::getDecrypted($dom_sts, $xpath, $token, $private);

if ($token != NULL) {
    
    $token = $dom_sts->saveXML($token);
        
    $body_org = KOMBIT::getBodyBrugerLaes('f484ab2a-5fc7-4169-8641-611ce7836267');
    $header_org = KOMBIT::getHeader($endpoint_org, $action_org, $token);
    
    $request_org = <<<XML
    <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">$header_org$body_org</s:Envelope>
    XML;
            
    $request_org_signed = KOMBIT::getRequestSigned($request_org, $private);
       
    $response_org = HTTP::doSOAP($endpoint_org, $request_org_signed, $action_org);
    
     /**
     * -----------------------------------------------------------------------
     */
    
    
    echo '<html><body><div style="display: block; ">';
    
    echo '<div style="display: block;">';
    if (strpos($response_org, 'Fault') !== false) {
        echo '<h2 style="color: red; text-align: center;">Failure</h2>';
    } else {
        echo '<h2 style="color: green; text-align: center;">Succes</h2>';        
    }
    
    echo '<div style="float: left"><label for="textXml3">Request:</label><br><textarea id="txtXml3" rows="90" cols="120" readonly="readonly" style="padding: 10px;">'.$request_org_signed.'</textarea></div>';
    echo '<div style="float: right"><label for="textXml4">Response:</label><br><textarea id="txtXml4" rows="90" cols="120" readonly="readonly" style="padding: 10px;">'.$response_org.'</textarea></div>';
    
    echo '</div></body></html>';
}

?>