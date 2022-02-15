<?php

class KOMBIT2 {

    const TOKENTYPE_SAML11 = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1';
    const TOKENTYPE_SAML20 = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0';
    const TOKENTYPE_STATUS = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Status';

    const KEYTYPE_SYMMETRIC = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey';
    const KEYTYPE_BEARER    = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer';
    const KEYTYPE_PUBLIC    = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey';

    static function getBodyBrugerLaes($uuid) {
        
        $body_id = self::gen_uuid();
        
        return <<<XML
<s:Body u:Id="_1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <LaesInput xmlns="http://stoettesystemerne.dk/organisation/bruger/6/">
        <UUIDIdentifikator xmlns="urn:oio:sagdok:3.0.0">$uuid</UUIDIdentifikator>
    </LaesInput>
</s:Body>
XML;        
    }

    static function getHeader2($to, $action, $token_raw) {
        
        $_timestamp = self::getTimestampHeader(self::gen_uuid());
        $_action = '<a:Action s:mustUnderstand="1" u:Id="_2">'.$action.'</a:Action>';
        $_message = '<a:MessageID u:Id="_3">urn:uuid:'.self::gen_uuid().'</a:MessageID>';
        $_reply = '<a:ReplyTo u:Id="_4"><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>';
        $_to = '<a:To s:mustUnderstand="1" u:Id="_5">'.$to.'</a:To>';
       
        $trans_uuid = self::gen_uuid();
        
        // TODO: Make both below dynamic with parameters.... maybe ns (namespaces) vary from service to service... must generate request from WSDL?
        $_request_header = <<<XML
<h:RequestHeader xmlns:h="http://kombit.dk/xml/schemas/RequestHeader/1/" xmlns="http://kombit.dk/xml/schemas/RequestHeader/1/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <TransactionUUID>$trans_uuid</TransactionUUID>
</h:RequestHeader>
XML;
        
        $d_t = new DOMDocument();
        $d_t->loadXML($token_raw);
        $token_uuid = self::getDocEleId($d_t->documentElement);
        
        return <<<XML
<s:Header>
    <sbf:Framework xmlns:ns1="urn:liberty:sb:profile" xmlns:sbf="urn:liberty:sb:2006-08" ns1:profile="urn:liberty:sb:profile:basic" version="2.0"/>
    $_action
    $_request_header
    $_message
    $_reply
    $_to
    <o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
        <o:SecurityTokenReference b:TokenType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0" u:Id="_str$token_uuid" xmlns:b="http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd">
            <o:KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID">$token_uuid</o:KeyIdentifier>
        </o:SecurityTokenReference>
        $_timestamp
        $token_raw
        <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
            <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod>
                <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></SignatureMethod>
            </SignedInfo>
            <SignatureValue></SignatureValue>
            <KeyInfo>
                <o:SecurityTokenReference b:TokenType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0" xmlns:b="http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd">
                    <o:KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID">$token_uuid</o:KeyIdentifier>
                </o:SecurityTokenReference>
            </KeyInfo>
        </Signature>      
    </o:Security>
</s:Header>
XML;
    }
    
    static function getRequestSigned($request_simple, $priv_key) {
        
        $d_r = new DOMDocument();
        $d_r->preserveWhiteSpace = false;
        $d_r->formatOutput = true;
        $d_r->loadXML($request_simple);
        
        $signature_uuid = self::gen_uuid();
        $key_info_uuid = self::gen_uuid();
        
        $sig_ele = $d_r->getElementsByTagName('Signature')[1];
        $si_ele = $sig_ele->getElementsByTagName('SignedInfo')[0];
        
        $referenceIds = array('Body', 'Action', 'MessageID', 'ReplyTo', 'To', 'Timestamp', 'SecurityTokenReference');
        
        foreach ($referenceIds as &$value) {
            $isSTR = ($value == 'SecurityTokenReference');
            //$isSTR = (strpos($tag_id, 'str_') !== false);
            $tags = $d_r->getElementsByTagName($value);
            
            //if(sizeof($tags) > 1) { echo "ERROR: ".$value. " - ". sizeof($tags); }
            
            $tag = $tags[0];
            $tag_id = self::getDocEleId($tag);
            
            if($isSTR) {
                $tag = $d_r->getElementsByTagName('Assertion')[0];
            } 
            
            $canonicalXml = $tag->C14N(TRUE, FALSE);
        
            $digestValue = base64_encode(openssl_digest($canonicalXml, 'SHA256', false));
            
            $reference = $si_ele->appendChild($d_r->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'Reference'));
            $reference->setAttribute('URI', "#{$tag_id}");
            $transforms = $reference->appendChild($d_r->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'Transforms'));
            $transform = $transforms->appendChild($d_r->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'Transform'));
            
            if($isSTR) {
                $transform->setAttribute('Algorithm', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform');
                $transformationParameter = $transform->appendChild($d_r->createElementNS('http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd', 'TransformationParameters'));
                $canonicalizationMethod = $transformationParameter->appendChild($d_r->createELementNS('http://www.w3.org/2000/09/xmldsig#','CanonicalizationMethod'));
                $canonicalizationMethod->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');
            } else {
                $transform->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');
            }
            
            $method = $reference->appendChild($d_r->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'DigestMethod'));
            $method->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256');
            $reference->appendChild($d_r->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'DigestValue', $digestValue));
        }
        
        $si_ele_can = $si_ele->C14N(TRUE, FALSE);
        
        openssl_sign($si_ele_can, $signatureValue, $priv_key, 'sha256WithRSAEncryption'); // OPENSSL_ALGO_SHA256 OR 'RSA-SHA256'
        $signatureValue = base64_encode($signatureValue);
        
        // Insert signaturevalue 
        $sig_ele->getElementsByTagName('SignatureValue')[0]->nodeValue = $signatureValue;
        
        return $d_r->saveXML($d_r->documentElement);
        
    }

    // Extract "Id" attribute from xml data
    static function getDocEleId($docEle) {
        for ($i = 0; $i < $docEle->attributes->length; ++$i) {
            if(strpos($docEle->attributes->item($i)->name, 'Id') !== false || strpos($docEle->attributes->item($i)->name, 'ID') !== false) {
                return $docEle->attributes->item($i)->value;
            }
        }
        return null;
    }
    
    static function getReferenceByTag($tagName, $request) {

        $dom = new DOMDocument();
        $dom->loadXML($request);
        $tag = $dom->getElementsByTagName($tagName)[0];
        
        $refURI = self::getDocEleId($tag);
        $isSTR = (strpos($refURI, 'str_') !== false);
                
        if($isSTR) {
            $tag = $dom->getElementsByTagName('Assertion')[0];
        } 
        
        $canonicalXml = $tag->C14N(TRUE, FALSE);
            
        $digestValue = base64_encode(openssl_digest($canonicalXml, 'SHA256', false));
                
        $transformXml = ($isSTR) ? '<Transform Algorithm="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform"><o:TransformationParameters xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod></o:TransformationParameters></Transform>' : '<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></Transform>';
      
        return <<<XML
<Reference URI="#$refURI">
    <Transforms>$transformXml</Transforms>
    <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></DigestMethod>
    <DigestValue>$digestValue</DigestValue>
</Reference>
XML;   
    }

    static function getTimestamp($offset = 0) {
            return gmdate("Y-m-d\TH:i:s\Z", time() + $offset);
    }

    static function getTimestampHeader($timestampID = "_0") {
        $c = self::getTimestamp();
        $e = self::getTimestamp(300);
        return <<<XML
<u:Timestamp u:Id="uuid-$timestampID">
    <u:Created>$c</u:Created>
    <u:Expires>$e</u:Expires>
</u:Timestamp>
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
}

?>