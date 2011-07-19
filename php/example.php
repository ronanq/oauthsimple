<?php
///////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
// Xero API OAuth Authorization using the OAuthSimple library
//
// Author: Guido Schlabitz
// Email: guido.schlabitz@gmail.com
//
// This example uses the OAuthSimple library for PHP
// found here:  http://unitedHeroes.net/OAuthSimple
//
// For more information about the OAuth process for web applications
// accessing Google APIs, read this guide:
// http://code.google.com/apis/accounts/docs/OAuth_ref.html
//
//////////////////////////////////////////////////////////////////////
require 'OAuthSimple.php';
require 'XeroOAuth.php';
$oauthObject = new OAuthSimple();

// As this is an example, I am not doing any error checking to keep 
// things simple.  Initialize the output in case we get stuck in
// the first step.
$output = 'Authorizing...';

// Fill in your API key/consumer key you received when you registered your 
// application with Xero.
/*$signatures = array( 'consumer_key'     => 'UK55RMPFGBKDME73PDNH5WM5CTLNDW',
                     'shared_secret'    => 'I6IDSTKK3XHUJKUPEAR4S9VNLO4754',
                     'rsa_private_key'	=> BASE_PATH . '/certs/privatekey.pem',
                     'rsa_public_key'	=> BASE_PATH . '/certs/publickey.cer');*/
# Define which app type you are using: 
# Private - private app method
# Public - standard public app method
# Partner - partner app method
# Partner_Mac - dev flavour of partner to get around Mac OS X issues with openssl (not for production)                
define("XRO_APP_TYPE",     "Partner_Mac");

                     
switch (XRO_APP_TYPE) {
    case "Private":
    	$signatures = array( 'consumer_key'     => 'H3REUBTQFUJCSAMLJ1GWZN84RWOMB1',
              	      	 'shared_secret'    => 'BYACL6JG1XM0IPC3VOBZZWTYVG2RSN',
                	     'rsa_private_key'	=> BASE_PATH . '/certs/php-test-private-rq-privatekey.pem',
                     	 'rsa_public_key'	=> BASE_PATH . '/certs/php-test-private-rq-publickey.cer');
        $xro_settings = $xro_private_defaults;
        $_GET['oauth_verifier'] = 1;
       	$_COOKIE['oauth_token_secret'] =  $signatures['shared_secret'];
       	$_GET['oauth_token'] =  $signatures['consumer_key'];
        break;
    case "Public":
    $signatures = array( 'consumer_key'     => 'UK55RMPFGBKDME73PDNH5WM5CTLNDW',
                     'shared_secret'    => 'I6IDSTKK3XHUJKUPEAR4S9VNLO4754',
                     'rsa_private_key'	=> BASE_PATH . '/certs/php-test-private-rq-privatekey.pem',
                     'rsa_public_key'	=> BASE_PATH . '/certs/php-test-private-rq-publickey.cer');
        $xro_settings = $xro_defaults;
        break;
    case "Partner":
    	$signatures = array( 'consumer_key'     => 'YUP2MEROFLLXVPMSRBJXDHAPXEM6CU',
              	      	 'shared_secret'    => 'MTFLVIVWEI8ZEX0P7EO54IU414EXPF',
                	     'rsa_private_key'	=> BASE_PATH . '/certs/php-test-private-rq-privatekey.pem',
                     	 'rsa_public_key'	=> BASE_PATH . '/certs/php-test-private-rq-publickey.cer');
       
        $xro_settings = $xro_partner_defaults;
        break;
    case "Partner_Mac":
    	$signatures = array( 'consumer_key'     => 'YUP2MEROFLLXVPMSRBJXDHAPXEM6CU',
              	      	 'shared_secret'    => 'MTFLVIVWEI8ZEX0P7EO54IU414EXPF',
                	     'rsa_private_key'	=> BASE_PATH . '/certs/php-test-private-rq-privatekey.pem',
                     	 'rsa_public_key'	=> BASE_PATH . '/certs/php-test-private-rq-publickey.cer');
       
        $xro_settings = $xro_partner_mac_defaults;
        break;
}
          

// In step 3, a verifier will be submitted.  If it's not there, we must be
// just starting out. Let's do step 1 then.
if (!isset($_GET['oauth_verifier'])) {
    ///////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // Step 1: Get a Request Token
    //
    // Get a temporary request token to facilitate the user authorization 
    // in step 2. We make a request to the OAuthGetRequestToken endpoint,
    // submitting the scope of the access we need (in this case, all the 
    // user's calendars) and also tell Google where to go once the token
    // authorization on their side is finished.
    //
    $result = $oauthObject->sign(array(
        'path'      => $xro_settings['site'].$xro_consumer_options['request_token_path'],
        'parameters'=> array(
            'scope'         => $xro_settings['xero_url'],
            'oauth_callback'=> 'http://localhost/oauthsimple_rq/php/example.php',
            'oauth_signature_method' => $xro_settings['signature_method']),
        'signatures'=> $signatures));

    // The above object generates a simple URL that includes a signature, the 
    // needed parameters, and the web page that will handle our request.  I now
    // "load" that web page into a string variable.
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_VERBOSE, '1');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    //WARNING: this would prevent curl from detecting a 'man in the middle' attack
	curl_setopt ($ch, CURLOPT_SSL_VERIFYHOST, 0);
	curl_setopt ($ch, CURLOPT_SSL_VERIFYPEER, 0); 
	
	switch (XRO_APP_TYPE) {
    case "Private":
       
        break;
    case "Public":
       
        break;
    case "Partner":
       		curl_setopt ($ch, CURLOPT_SSLCERT, BASE_PATH . '/certs/entrust-cert.pem'); 
			curl_setopt ($ch, CURLOPT_SSLKEYPASSWD, '1234'); 
			curl_setopt ($ch, CURLOPT_SSLKEY, BASE_PATH . '/certs/entrust-private.pem'); 
        break;
    case "Partner_Mac":
        	//curl_setopt($ch, CURLOPT_CAINFO,  BASE_PATH .'/certs/ca.crt');
			//curl_setopt($ch, CURLOPT_FAILONERROR, 1); 
			// Partner app settings
			//curl_setopt($ch, CURLOPT_SSLKEYTYPE, 'PEM'); 
			//curl_setopt($ch, CURLOPT_SSLCERTPASSWD, '1234'); 
			curl_setopt ($ch, CURLOPT_SSLCERT, BASE_PATH . '/certs/entrust-cert.pem'); 
			curl_setopt ($ch, CURLOPT_SSLKEYPASSWD, '1234'); 
			curl_setopt ($ch, CURLOPT_SSLKEY, BASE_PATH . '/certs/entrust-private.pem'); 
        break;
}

	
	
	 
    if(isset($_GET['debug'])){
    //echo BASE_PATH . '/certs/entrust-private.pem' . '<br/>';
    	$fp = fopen(BASE_PATH . '/certs/clientCert-rq.pem',"r");
       	
		$file_contents = fread($fp,8192);
		//echo "<br/>" . $file_contents . '<br/>';
		fclose($fp);
    echo 'CURLOPT_SSLKEY: ' . CURLOPT_SSLKEY . '<br/>';
    echo 'CURLOPT_SSLCERT: ' . CURLOPT_SSLCERT . '<br/>';
    echo 'signed_url: ' . $result['signed_url'] . '<br/>';
    }
    
    curl_setopt($ch, CURLOPT_URL, $result['signed_url']);
    $r = curl_exec($ch);
    if(isset($_GET['debug'])){
    echo 'CURL ERROR: ' . curl_error($ch) . '<br/>';
    }

    curl_close($ch);

	if(isset($_GET['debug'])){
    echo 'CURL RESULT: ' . print_r($r) . '<br/>';
    }
    // We parse the string for the request token and the matching token
    // secret. Again, I'm not handling any errors and just plough ahead 
    // assuming everything is hunky dory.
    parse_str($r, $returned_items);
    $request_token = $returned_items['oauth_token'];
    $request_token_secret = $returned_items['oauth_token_secret'];

	 if(isset($_GET['debug'])){
    echo 'request_token: ' . $request_token . '<br/>';
    }
    
    // We will need the request token and secret after the authorization.
    // Google will forward the request token, but not the secret.
    // Set a cookie, so the secret will be available once we return to this page.
    setcookie("oauth_token_secret", $request_token_secret, time()+3600);
    //
    //////////////////////////////////////////////////////////////////////
    
    ///////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // Step 2: Authorize the Request Token
    //
    // Generate a URL for an authorization request, then redirect to that URL
    // so the user can authorize our access request.  The user could also deny
    // the request, so don't forget to add something to handle that case.
    $result = $oauthObject->sign(array(
        'path'      => $xro_settings['authorize_url'],
        'parameters'=> array(
            'oauth_token' => $request_token,
            'oauth_signature_method' => $xro_settings['signature_method']),
        'signatures'=> $signatures));

    // See you in a sec in step 3.
    if(isset($_GET['debug'])){
    echo 'signed_url: ' . $result[signed_url];
    }else{
    header("Location:$result[signed_url]");
    }
    exit;
    //////////////////////////////////////////////////////////////////////
}
else {
    ///////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // Step 3: Exchange the Authorized Request Token for a Long-Term
    //         Access Token.
    //
    // We just returned from the user authorization process on Google's site.
    // The token returned is the same request token we got in step 1.  To 
    // sign this exchange request, we also need the request token secret that
    // we baked into a cookie earlier. 
    //

    // Fetch the cookie and amend our signature array with the request
    // token and secret.
    $signatures['oauth_secret'] = $_COOKIE['oauth_token_secret'];
    $signatures['oauth_token'] = $_GET['oauth_token'];
    
    // only need to do this for non-private apps
    if(XRO_APP_TYPE!='Private'){
	// Build the request-URL...
	$result = $oauthObject->sign(array(
		'path'		=> $xro_settings['site'].$xro_consumer_options['access_token_path'],
		'parameters'=> array(
			'oauth_verifier' => $_GET['oauth_verifier'],
			'oauth_token'	 => $_GET['oauth_token'],
			'oauth_signature_method' => $xro_settings['signature_method']),
		'signatures'=> $signatures));

	// ... and grab the resulting string again. 
	$ch = curl_init();
	curl_setopt($ch, CURLOPT_VERBOSE, '1');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    //WARNING: this would prevent curl from detecting a 'man in the middle' attack
	curl_setopt ($ch, CURLOPT_SSL_VERIFYHOST, 0);
	curl_setopt ($ch, CURLOPT_SSL_VERIFYPEER, 0); 
	curl_setopt ($ch, CURLOPT_SSLCERT, BASE_PATH . '/certs/entrust-cert.pem'); 
			curl_setopt ($ch, CURLOPT_SSLKEYPASSWD, '1234'); 
			curl_setopt ($ch, CURLOPT_SSLKEY, BASE_PATH . '/certs/entrust-private.pem'); 
	curl_setopt($ch, CURLOPT_URL, $result['signed_url']);
	$r = curl_exec($ch);
print_r($r);
	// Voila, we've got a long-term access token.
	parse_str($r, $returned_items);		   
	$access_token = $returned_items['oauth_token'];
	$access_token_secret = $returned_items['oauth_token_secret'];
    }else{
    $access_token = $signatures['oauth_token'];
	$access_token_secret = $signatures['oauth_secret'];
    }
    
    // We can use this long-term access token to request Google API data,
    // for example, a list of calendars. 
    // All Google API data requests will have to be signed just as before,
    // but we can now bypass the authorization process and use the long-term
    // access token you hopefully stored somewhere permanently.
    $signatures['oauth_token'] = $access_token;
    $signatures['oauth_secret'] = $access_token_secret;
    //////////////////////////////////////////////////////////////////////
    
    // Example Xero API Access:
    // This will build a link to an RSS feed of the users calendars.
    $oauthObject->reset();
    $result = $oauthObject->sign(array(
        'path'      => $xro_settings['xero_url'].'/Accounts',
        //'parameters'=> array('Where' => 'Type%3d%3d%22BANK%22'),
        'parameters'=> array(
        'oauth_token' => $access_token,
			'oauth_signature_method' => $xro_settings['signature_method']),
        'signatures'=> $signatures));
print_r($_POST);
    // Instead of going to the list, I will just print the link along with the 
    // access token and secret, so we can play with it in the sandbox:
    // http://googlecodesamples.com/oauth_playground/
    //
   
    
    $ch = curl_init();
	curl_setopt($ch, CURLOPT_VERBOSE, '1');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    //WARNING: this would prevent curl from detecting a 'man in the middle' attack
	curl_setopt ($ch, CURLOPT_SSL_VERIFYHOST, 0);
	curl_setopt ($ch, CURLOPT_SSL_VERIFYPEER, 0); 
	curl_setopt ($ch, CURLOPT_SSLCERT, BASE_PATH . '/certs/entrust-cert.pem'); 
			curl_setopt ($ch, CURLOPT_SSLKEYPASSWD, '1234'); 
			curl_setopt ($ch, CURLOPT_SSLKEY, BASE_PATH . '/certs/entrust-private.pem'); 
    curl_setopt($ch, CURLOPT_URL, $result['signed_url']);
    $output = "<p>Access Token: $access_token<BR>
                  Token Secret: $access_token_secret</p>
               <p><a href='$result[signed_url]'>GET Accounts</a></p>";
    echo "firing<br/>";
    $r = curl_exec($ch);
    print_r($r);
    curl_close($ch);
    
}        
?>
<HTML>
<BODY>
<?php echo $output;?>
</BODY>
</HTML>
