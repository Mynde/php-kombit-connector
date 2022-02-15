<?php

class KOMBIT {

    const TOKENTYPE_SAML11 = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1';
    const TOKENTYPE_SAML20 = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0';
    const TOKENTYPE_STATUS = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Status';

    const KEYTYPE_SYMMETRIC = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey';
    const KEYTYPE_BEARER    = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer';
    const KEYTYPE_PUBLIC    = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey';

    static function getBodyBrugerLaes($uuid) {
        
        $body_id = KOMBIT::gen_uuid();
        
        return <<<XML
<soap:Body xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="_$body_id">
    <ns4:LaesInput xmlns="http://kombit.dk/xml/schemas/RequestHeader/1/" xmlns:ns2="urn:oio:sagdok:3.0.0" xmlns:ns3="http://stoettesystemerne.dk/klassifikation/klasse/6/" xmlns:ns4="http://stoettesystemerne.dk/organisation/bruger/6/" xmlns:ns5="http://stoettesystemerne.dk/organisation/6/" xmlns:ns6="urn:oio:sts:6" xmlns:ns7="urn:oio:sts:part:6">
      <ns2:UUIDIdentifikator>$uuid</ns2:UUIDIdentifikator>
    </ns4:LaesInput>
</soap:Body>
XML;        
    }

    static function getHeader($to, $action, $token) {
        
        $_timestamp = KOMBIT::getTimestampHeader(KOMBIT::gen_uuid());
        $_action = '<Action xmlns="http://www.w3.org/2005/08/addressing" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="_'.KOMBIT::gen_uuid().'">'.$action.'</Action>';
        $_message = '<MessageID xmlns="http://www.w3.org/2005/08/addressing" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="_'.KOMBIT::gen_uuid().'">urn:uuid:'.KOMBIT::gen_uuid().'</MessageID>';
        $_to = '<To xmlns="http://www.w3.org/2005/08/addressing" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="_'.KOMBIT::gen_uuid().'">'.$to.'</To>';
        $_reply = '<ReplyTo xmlns="http://www.w3.org/2005/08/addressing" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="_'.KOMBIT::gen_uuid().'"><Address>http://www.w3.org/2005/08/addressing/anonymous</Address></ReplyTo>';
        
        // TODO: Make both below dynamic with parameters.... maybe ns (namespaces) vary from service to service... must generate request from WSDL?
        $_request_header = '<RequestHeader xmlns="http://kombit.dk/xml/schemas/RequestHeader/1/" xmlns:ns2="urn:oio:sagdok:3.0.0" xmlns:ns3="http://stoettesystemerne.dk/klassifikation/klasse/6/" xmlns:ns4="http://stoettesystemerne.dk/organisation/bruger/6/" xmlns:ns5="http://stoettesystemerne.dk/organisation/6/" xmlns:ns6="urn:oio:sts:6" xmlns:ns7="urn:oio:sts:part:6"><TransactionUUID>'.KOMBIT::gen_uuid().'</TransactionUUID></RequestHeader>';
        
        $d_t = new DOMDocument();
        $d_t->loadXML($token);
        
        $token_uuid = self::getDocEleId($d_t->documentElement);
        $_security_token_ref = '<wsse:SecurityTokenReference xmlns:b="http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd" b:TokenType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0" wsu:Id="_str'.$token_uuid.'"><wsse:KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID">'.$token_uuid.'</wsse:KeyIdentifier></wsse:SecurityTokenReference>';
        
        // In header: ?? <sbf:Framework xmlns:ns1="urn:liberty:sb:profile" xmlns:sbf="urn:liberty:sb:2006-08" ns1:profile="urn:liberty:sb:profile:basic" version="2.0"/>
        return <<<XML
<soap:Header>
    $_action
    $_message
    $_to
    $_reply
    $_request_header
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" soap:mustUnderstand="true">
        $_timestamp
        $token
        $_security_token_ref
    </wsse:Security>
</soap:Header>
XML;
    }
    
     static function getRequestSigned($request_simple, $priv_key) {
        
        $d_r = new DOMDocument();
        $d_r->loadXML($request_simple);
        
        $token_uuid = KOMBIT::getDocEleId($d_r->getElementsByTagName('Assertion')[0]);
        $signature_uuid = KOMBIT::gen_uuid();
        $key_info_uuid = KOMBIT::gen_uuid();
        
        $references = "";
        $references .= KOMBIT::getReferenceByTag('Body', $request_simple); //2
        $references .= KOMBIT::getReferenceByTag('To', $request_simple); //3
        $references .= KOMBIT::getReferenceByTag('ReplyTo', $request_simple); //4
        $references .= KOMBIT::getReferenceByTag('MessageID', $request_simple); // 5
        $references .= KOMBIT::getReferenceByTag('Action', $request_simple); // 6 //2
        //$references .= KOMBIT::getReferenceByTag('Assertion', $request_simple); 
        $references .= KOMBIT::getReferenceByTag('Timestamp', $request_simple); //1
        $references .= KOMBIT::getReferenceByTag('SecurityTokenReference', $request_simple);
        
        $signature = <<<XML
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" Id="SIG-$signature_uuid">
    <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        $references
    </ds:SignedInfo>
    <ds:SignatureValue></ds:SignatureValue>
    <ds:KeyInfo Id="KI-$key_info_uuid">
        <SecurityTokenReference xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:b="http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd" b:TokenType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0">
            <KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID">$token_uuid</KeyIdentifier>
        </SecurityTokenReference>
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
        
        $refURI = KOMBIT::getDocEleId($tag);
        $isSTR = (strpos($refURI, '_str_') !== false);
        
        $canonicalXml = null;
        
        if($isSTR) {
            
            $tag = $dom->getElementsByTagName('Assertion')[0];
                        
        } 
        
        $canonicalXml = $tag->C14N(TRUE, FALSE);
            
        $digestValue = base64_encode(openssl_digest($canonicalXml, 'SHA256', false));
                
        $transformXml = ($isSTR) ? '<ds:Transform Algorithm="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform"><wsse:TransformationParameters><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></wsse:TransformationParameters></ds:Transform>' : '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform>';
      
        return <<<XML
<ds:Reference URI="#$refURI">
    <ds:Transforms>$transformXml</ds:Transforms>
    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <ds:DigestValue>$digestValue</ds:DigestValue>
</ds:Reference>
XML;   
    }

    static function getTimestamp($offset = 0) {
            return gmdate("Y-m-d\TH:i:s\Z", time() + $offset);
    }

    static function getTimestampHeader($timestampID = "_0") {
        $c = KOMBIT::getTimestamp();
        $e = KOMBIT::getTimestamp(300);
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
}

?>