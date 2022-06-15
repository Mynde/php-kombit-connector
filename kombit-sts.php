<?php

class STS {

    const TOKENTYPE_SAML11 = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1';
    const TOKENTYPE_SAML20 = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0';
    const TOKENTYPE_STATUS = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Status';

    const KEYTYPE_SYMMETRIC = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey';
    const KEYTYPE_BEARER    = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer';
    const KEYTYPE_PUBLIC    = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey';

    static function getRST($endpoint_sts, $appliesTo, $cvr, $issuer, $cert_key, $action = 'Issue', $keyType = self::KEYTYPE_PUBLIC, $tokenType = self::TOKENTYPE_SAML20) {
        
        $cert_key = str_replace(array("\r", "\n"), '', $cert_key);
        $body_id = self::gen_uuid();
        
        $body = <<<XML
<soap:Body xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="_$body_id">
    <wst:RequestSecurityToken xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
        <wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/$action</wst:RequestType>
        <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
            <wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">
              <wsa:Address>$appliesTo</wsa:Address>
            </wsa:EndpointReference>
        </wsp:AppliesTo>
        <Claims xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512" Dialect="http://docs.oasis-open.org/wsfed/authorization/200706/authclaims">
            <ClaimType xmlns="http://docs.oasis-open.org/wsfed/authorization/200706" Uri="dk:gov:saml:attribute:CvrNumberIdentifier">
                <Value xmlns="http://docs.oasis-open.org/wsfed/authorization/200706">$cvr</Value>
            </ClaimType>
        </Claims>
        <wst:TokenType>$tokenType</wst:TokenType>
        <wst:KeyType>$keyType</wst:KeyType>
        <wst:UseKey>
            <wsse:BinarySecurityToken xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3">$cert_key</wsse:BinarySecurityToken>
        </wst:UseKey>
    </wst:RequestSecurityToken>
</soap:Body>
XML;    
        
        $header = self::getRSTHeader($endpoint_sts, $cert_key);

        return <<<XML
        <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
            $header
            $body
        </soap:Envelope>
        XML;
    }

    static function getRSTHeader($to, $cert_key, $action = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue') {
        
        $_token = self::getCertificateToken($cert_key, self::gen_uuid());
        $_timestamp = self::getTimestampHeader(self::gen_uuid());
        $_action = '<Action xmlns="http://www.w3.org/2005/08/addressing" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="_'.self::gen_uuid().'">'.$action.'</Action>';
        $_message = '<MessageID xmlns="http://www.w3.org/2005/08/addressing" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="_'.self::gen_uuid().'">urn:uuid:'.self::gen_uuid().'</MessageID>';
        $_reply = '<ReplyTo xmlns="http://www.w3.org/2005/08/addressing" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="_'.self::gen_uuid().'"><Address>http://www.w3.org/2005/08/addressing/anonymous</Address></ReplyTo>';
        $_to = '<To xmlns="http://www.w3.org/2005/08/addressing" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="_'.self::gen_uuid().'">'.$to.'</To>';

        // In header: ?? <sbf:Framework xmlns:ns1="urn:liberty:sb:profile" xmlns:sbf="urn:liberty:sb:2006-08" ns1:profile="urn:liberty:sb:profile:basic" version="2.0"/>
        return <<<XML
<soap:Header>
    $_action
    $_message
    $_to
    $_reply
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" soap:mustUnderstand="true">
        $_timestamp
        $_token
    </wsse:Security>
</soap:Header>
XML;
    }
    
    static function getRSTSigned($request_simple, $priv_key) {
        
        $d_r = new DOMDocument();
        $d_r->preserveWhiteSpace = true;
        $d_r->formatOutput = true;
        $d_r->loadXML($request_simple);
        
        $token_uuid = self::getDocEleId($d_r->getElementsByTagName('BinarySecurityToken')[0]);
        $signature_uuid = self::gen_uuid();
        $key_info_uuid = self::gen_uuid();
        $tok_ref_uuid = self::gen_uuid();
        
        $references = "";
        $references .= self::getReferenceByTag('Timestamp', $request_simple); //1
        $references .= self::getReferenceByTag('Body', $request_simple); //2
        $references .= self::getReferenceByTag('To', $request_simple); //3
        $references .= self::getReferenceByTag('ReplyTo', $request_simple); //4
        $references .= self::getReferenceByTag('MessageID', $request_simple); // 5
        $references .= self::getReferenceByTag('Action', $request_simple); // 6
        $references .= self::getReferenceByTag('BinarySecurityToken', $request_simple); // 7

        $signedInfo = <<<XML
<ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    $references
</ds:SignedInfo>
XML;
        
        $signature = <<<XML
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="SIG-$signature_uuid">
    $signedInfo
    <ds:SignatureValue></ds:SignatureValue>
    <ds:KeyInfo Id="KI-$key_info_uuid">
        <wsse:SecurityTokenReference xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="STR-$tok_ref_uuid">
          <wsse:Reference URI="#$token_uuid" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/>              
        </wsse:SecurityTokenReference>
    </ds:KeyInfo>
</ds:Signature>
XML;
        $d_s = new DOMDocument();
        $d_s->loadXML($signature);
        $si_ele = $d_s->getElementsByTagName('SignedInfo')[0];
        $si_ele_can = $si_ele->C14N(TRUE, FALSE);
        
        openssl_sign($si_ele_can, $signatureValue, $priv_key, 'sha256WithRSAEncryption'); // OPENSSL_ALGO_SHA256 OR 'RSA-SHA256'
        $signatureValue = base64_encode($signatureValue);
        
        // Insert signaturevalue 
        $d_s->getElementsByTagName('SignatureValue')[0]->nodeValue = $signatureValue;
                
        // Insert signature in header....
        $node = $d_r->importNode($d_s->documentElement, true);
        
        $d_r->getElementsByTagName('Security')[0]->appendChild($node);
        
        // In header: ?? <sbf:Framework xmlns:ns1="urn:liberty:sb:profile" xmlns:sbf="urn:liberty:sb:2006-08" ns1:profile="urn:liberty:sb:profile:basic" version="2.0"/>
        return $d_r->saveXML($d_r->documentElement);
    }

    // Extract "Id" attribute from xml data
    static function getDocEleId($docEle) {
        for ($i = 0; $i < $docEle->attributes->length; ++$i) {
            if(strpos($docEle->attributes->item($i)->name, 'Id') !== false) {
                return $docEle->attributes->item($i)->value;
            }
        }
        return null;
    }
    
    static function getReferenceByTag($tagName, $request) {

        $dom = new DOMDocument();
        $dom->loadXML($request);
        $tag = $dom->getElementsByTagName($tagName)[0];
        $canonicalXml = $tag->C14N(TRUE, FALSE);
        
        $digestValue = base64_encode(openssl_digest($canonicalXml, 'SHA256', true));
        
        // Extract "Id" attribute from xml data
        $refURI = self::getDocEleId($tag);

        return <<<XML
<ds:Reference URI="#$refURI">
    <ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms>
    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <ds:DigestValue>$digestValue</ds:DigestValue>
</ds:Reference>
XML; 
    }

    static function getCertificateToken($enc_cert_content, $token_tag_uuid) {
            $enc_cert_content = str_replace(array("\r", "\n"), '', $enc_cert_content);
            return <<<XML
<wsse:BinarySecurityToken xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" wsu:Id="X509-$token_tag_uuid">$enc_cert_content</wsse:BinarySecurityToken>
XML;
    }

    static function getTimestamp($offset = 0) {
            return gmdate("Y-m-d\TH:i:s\Z", time() + $offset);
    }

    static function getTimestampHeader($timestampID = "_0") {
        $c = self::getTimestamp();
        $e = self::getTimestamp(300);
        return <<<XML
<wsu:Timestamp wsu:Id="TS-$timestampID">
    <wsu:Created>$c</wsu:Created>
    <wsu:Expires>$e</wsu:Expires>
</wsu:Timestamp>
XML;
}
   static function gen_uuid() {
        return sprintf( '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            // 32 bits for "time_low"
            mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ),

            // 16 bits for "time_mid"
            mt_rand( 0, 0xffff ),

            // 16 bits for "time_hi_and_version",
            // four most significant bits holds version number 4
            mt_rand( 0, 0x0fff ) | 0x4000,

            // 16 bits, 8 bits for "clk_seq_hi_res",
            // 8 bits for "clk_seq_low",
            // two most significant bits holds zero and one for variant DCE1.1
            mt_rand( 0, 0x3fff ) | 0x8000,

            // 48 bits for "node"
            mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff )
        );
    }

    /**
     * -------------------------------------------------------------------
     * Reading responses
     * ---------------------------------------------------------------------
     */

    static function parseRSTR($result) {
        $dom = new DOMDocument();
        $dom->loadXML($result);
        $doc = $dom->documentElement;
        $xpath = new DOMXpath($dom);
        $xpath->registerNamespace('s', 'http://www.w3.org/2003/05/soap-envelope');
        $xpath->registerNamespace('wst', 'http://docs.oasis-open.org/ws-sx/ws-trust/200512');
        $xpath->registerNamespace('wsse', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd');
        $token = $xpath->query('/s:Envelope/s:Body/wst:RequestSecurityTokenResponseCollection/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken', $doc);
        $proofKey = $xpath->query('/s:Envelope/s:Body/wst:RequestSecurityTokenResponseCollection/wst:RequestSecurityTokenResponse/wst:RequestedProofToken/wst:BinarySecret', $doc);
        if ($proofKey->length > 0) {
                $proofKey = base64_decode($proofKey->item(0)->textContent);
        } else {
                $proofKey = NULL;
        }
        return array ($dom, $xpath, $token->item(0), $proofKey);
    }

    static function getDecrypted($dom, $xpath, $token, $pkey, $type = self::TOKENTYPE_SAML20) {
        $doc = $dom->documentElement;
        $xpath->registerNamespace('xenc', 'http://www.w3.org/2001/04/xmlenc#');
        $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
        $xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
        $xpath_prefix = '/s:Envelope/s:Body/wst:RequestSecurityTokenResponseCollection/wst:RequestSecurityTokenResponse/wst:RequestedSecurityToken';
        $xpath_key = '/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue';
        $xpath_encrypted = '/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue';
        switch ($type) {
                case self::TOKENTYPE_SAML11:
                        $xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:1.0:assertion');
                        $xpath_suffix = '';
                        break;
                case self::TOKENTYPE_SAML20:
                        $xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
                        $xpath_suffix = '/saml:EncryptedAssertion';
                        break;
        }
        $key = $xpath->query($xpath_prefix . $xpath_suffix . $xpath_key, $doc);		
        if ($key->length > 0) {
                // decrypt encrypted token
                $key = $key->item(0)->textContent;

                $encrypted = $xpath->query($xpath_prefix . $xpath_suffix . $xpath_encrypted, $doc);
                $encrypted = $encrypted->item(0)->textContent;

                $encryptedData = base64_decode($encrypted);
                $encryptedKey= base64_decode($key);

                // TODO ?: get the padding from
                //       <e:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p">

                openssl_private_decrypt($encryptedKey, $sessionKey, $pkey, OPENSSL_PKCS1_OAEP_PADDING);
                while ($msg = openssl_error_string()) echo $msg . "\n";
                openssl_free_key($privateKey);

                $cipher = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
                $ivSize = mcrypt_enc_get_iv_size($cipher);
                $iv = substr($encryptedData, 0, $ivSize);

                mcrypt_generic_init($cipher, $sessionKey, $iv);

                $decryptedData = mdecrypt_generic($cipher, substr($encryptedData, $ivSize));
                mcrypt_generic_deinit($cipher);
                mcrypt_module_close($cipher);

                $dataLen = strlen($decryptedData);
                $paddingLength = substr($decryptedData, $dataLen - 1, 1);
                $data = substr($decryptedData, 0, $dataLen - ord($paddingLength));

                $dom = new DOMDocument();
                $dom->loadXML($data);
                $token = $dom->documentElement;

        } else {
                $xpath_suffix = '/saml:Assertion';
                $data = $xpath->query($xpath_prefix . $xpath_suffix, $doc);
                if ($data->length > 0) $token = $data->item(0);
        }

        return array($dom, $token);
    }
}

?>