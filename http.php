<?php 

class HTTP {
	
	static $HTTP_DEBUG = 0;
        
	// don't use this in production!
	static $HTTP_SSL_VERIFY_PEER = 1;
	static $HTTP_SSL_VERIFYHOST = 1;

	private $ch;

	private function HTTP($url, $username, $password) {
		$this->ch = curl_init($url);
		curl_setopt($this->ch, CURLOPT_VERBOSE, HTTP::$HTTP_DEBUG);
		curl_setopt($this->ch, CURLOPT_SSL_VERIFYPEER, HTTP::$HTTP_SSL_VERIFY_PEER);
		curl_setopt($this->ch, CURLOPT_SSL_VERIFYHOST, HTTP::$HTTP_SSL_VERIFYHOST);
		curl_setopt($this->ch, CURLOPT_RETURNTRANSFER, 1);
//		curl_setopt($this->ch, CURLOPT_HEADER, 1);
		if ( ($username != NULL) and ($password != NULL) ) {
			curl_setopt($this->ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC ) ; 
			curl_setopt($this->ch, CURLOPT_USERPWD, $username . ':' . $password); 
		}
		curl_setopt($this->ch, CURLOPT_URL, $url);
	}
	
	private function doExec($url, $post = NULL, $cookies = NULL) {
            
		if ($post != NULL) {
                    // workaround curl version peculiarity
                    curl_setopt($this->ch, CURLOPT_POST, true);
                    curl_setopt($this->ch, CURLOPT_POSTFIELDS, $post);
		}
                
		if ($cookies != NULL) {
		    curl_setopt($this->ch, CURLOPT_COOKIEJAR, $cookies);
                    curl_setopt($this->ch, CURLOPT_COOKIEFILE, $cookies);			
		}
                                
		$result = curl_exec($this->ch);
                
                print_r(curl_error($this->ch));
                
                $httpcode = curl_getinfo($this->ch, CURLINFO_HTTP_CODE);
                
		curl_close($this->ch);
                
		if (HTTP::$HTTP_DEBUG) {
			print "\n # Response from $url ($httpcode):#\n\n";
			print $result;
			print "\n\n";
		}
		return $result;
	}

	private function getHandle() {
		return $this->ch;
	}
	
	static private function getInstance($url, $username = NULL, $password = NULL) {
		return new HTTP($url, $username, $password);
	}

	static public function doGet($url, $cookies = NULL) {
		$o = HTTP::getInstance($url);
		if (HTTP::$HTTP_DEBUG) {
			print "\n # GET Request to $url: #\n\n";
			print $url;
			print "\n\n";
		}		
		return $o->doExec($url, NULL, $cookies);
	}

	static public function doPost($url, $parms, $cookies = NULL) {
		$o = HTTP::getInstance($url);
		$content = '';
		foreach ($parms as $key => $value) {
			if ($content != '') $content .= '&';
			$content .= urlencode($key) . '=' . urlencode($value);
		}
		if (HTTP::$HTTP_DEBUG) {
			print "\n # POST Request to $url: #\n\n";
			print $content;
			print "\n\n";
		}		
		return $o->doExec($url, $content, $cookies);
	}
	
        static public function startsWith($string, $startString)
        {
            $len = strlen($startString);
            return (substr($string, 0, $len) === $startString);
        }
        
	static public function doSoap($url, $request, $action = NULL, $user = NULL, $password = NULL, $version = 'http://www.w3.org/2003/05/soap-envelope', $ctype = 'application/soap+xml') {
            $o = HTTP::getInstance($url, $user, $password);

            if (HTTP::$HTTP_DEBUG) {
                    print "\n # SOAP Request to $url: #<br><br><pre>";
                    var_dump($request);
                    print "</pre><br><br><br>";
            }
            
            curl_setopt($o->getHandle(), CURLOPT_SSLVERSION, 6);      
            
  
            if($action != NULL) {
                //array_push($headers, );
                $headers =  array('Content-Type: ' . $ctype . '; charset=utf-8; action="'.$action.'"', "Content-Length: ". strlen($request));
                // TODO: Needed?
                // openssl x509 -inform der -in "C:\Users\hmynderup\Documents\NetBeansProjects\KOMBITConnector\certificates\KOMBIT AS - test-ekstern-adgangsstyring.cer" -out "C:\Users\hmynderup\Documents\NetBeansProjects\KOMBITConnector\certificates\KOMBIT AS - test-ekstern-adgangsstyring.pem"
                curl_setopt($o->getHandle(), CURLOPT_CAINFO, "certificates/GlobalSign Root CA - R3.pem");
                curl_setopt($o->getHandle(), CURLOPT_CAINFO, "certificates/TRUST2408 OCES Primary CA.pem");
                curl_setopt($o->getHandle(), CURLOPT_CAINFO, "certificates/TRUST2408 Systemtest VII Primary CA.pem");
                curl_setopt($o->getHandle(), CURLOPT_CAINFO, "certificates/TRUST2408 Systemtest XXXIV CA.pem");
                curl_setopt($o->getHandle(), CURLOPT_CAINFO, "certificates/KOMBIT AS - test-ekstern-adgangsstyring.pem");
                curl_setopt($o->getHandle(), CURLOPT_CAINFO, "certificates/Organisation_T.pem");
            } else {
                $headers =  array('Content-Type: ' . $ctype . '; charset=utf-8', "Content-Length: ". strlen($request));
            }
            
            curl_setopt($o->getHandle(), CURLOPT_HTTPHEADER, $headers);

            $res = $o->doExec($url, $request);

            return $res;
	}
}
?>