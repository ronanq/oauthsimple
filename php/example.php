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

# set your callback url or set 'oob' if none required
define("OAUTH_CALLBACK",     'http://localhost/oauthsimple_rq/php/example.php');


# Set some standard curl options....
		$options[CURLOPT_VERBOSE] = 1;
    	$options[CURLOPT_RETURNTRANSFER] = 1;
    	$options[CURLOPT_SSL_VERIFYHOST] = 0;
    	$options[CURLOPT_SSL_VERIFYPEER] = 0;
                     
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
   	 	$signatures = array( 'consumer_key'     => 'MWSAN8S5AAFPMMNBV3DQIEWH4TM9FE',
              	      	 'shared_secret'    => 's',
                	     'rsa_private_key'	=> BASE_PATH . '/certs/rq-partner-app-2-privatekey.pem',
                     	 'rsa_public_key'	=> BASE_PATH . '/certs/rq-partner-app-2-publickey.cer');
        $xro_settings = $xro_partner_defaults;
        break;
    case "Partner_Mac":
    	$options[CURLOPT_SSLCERT] = BASE_PATH . '/certs/entrust-cert.pem';
    	$options[CURLOPT_SSLKEYPASSWD] = '1234';
    	$options[CURLOPT_SSLKEY] = BASE_PATH . '/certs/entrust-private.pem';
    	
    	
    	$signatures = array( 'consumer_key'     => 'MWSAN8S5AAFPMMNBV3DQIEWH4TM9FE',
              	      	 'shared_secret'    => 's',
                	     'rsa_private_key'	=> BASE_PATH . '/certs/rq-partner-app-2-privatekey.pem',
                     	 'rsa_public_key'	=> BASE_PATH . '/certs/rq-partner-app-2-publickey.cer');
       
        $xro_settings = $xro_partner_mac_defaults;
        break;
}
          
// bypass if we have an active session
session_start();
if ($_SESSION&&$_REQUEST['start']==1) {

	$signatures['oauth_token'] = $_SESSION['access_token'];
    $signatures['oauth_secret'] = $_SESSION['access_token_secret'];
    $signatures['oauth_session_handle'] = $_SESSION['oauth_session_handle'];
    //////////////////////////////////////////////////////////////////////
    
     if (!empty($_REQUEST['endpoint'])){
    // Example Xero API Access:
    $oauthObject->reset();
    $result = $oauthObject->sign(array(
        'path'      => $xro_settings['xero_url'].'/'.$_REQUEST['endpoint'].'/',
        //'parameters'=> array('Where' => 'Type%3d%3d%22BANK%22'),
        'parameters'=> array(
			'oauth_signature_method' => $xro_settings['signature_method']),
        'signatures'=> $signatures));
	$ch = curl_init();
	curl_setopt_array($ch, $options);
    curl_setopt($ch, CURLOPT_URL, $result['signed_url']);
	$r = curl_exec($ch);
	curl_close($ch);
	
	parse_str($r, $returned_items);		   
	$oauth_problem = $returned_items['oauth_problem'];
		if($oauth_problem){
			session_destroy();
		}
	
	echo 'CURL RESULT: <textarea cols="160" rows="40">' . $r . '</textarea><br/>';
	}
	
	// Example Xero API AccessToken swap:
	if (!empty($_REQUEST['action'])){
		$oauthObject->reset();
    	$result = $oauthObject->sign(array(
        	'path'      => $xro_settings['site'].$xro_consumer_options['access_token_path'],
        	'parameters'=> array(
            'scope'         => $xro_settings['xero_url'],
            'oauth_session_handle'	=> $signatures['oauth_session_handle'],
            'oauth_token'	=> $signatures['oauth_token'],
            'oauth_signature_method' => $xro_settings['signature_method']),
        'signatures'=> $signatures));
	$ch = curl_init();
	curl_setopt_array($ch, $options);
    curl_setopt($ch, CURLOPT_URL, $result['signed_url']);
	$r = curl_exec($ch);
	parse_str($r, $returned_items);		   
	$_SESSION['access_token'] = $returned_items['oauth_token'];
	$_SESSION['access_token_secret']   = $returned_items['oauth_token_secret'];
	$_SESSION['oauth_session_handle']   = $returned_items['oauth_session_handle'];
	if($returned_items['oauth_token']){
		echo "Refresh successful - new token: " . $returned_items['oauth_token'] . "<br/>";
		}
	curl_close($ch);
	}
	
}else{

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
            'oauth_callback'	=> OAUTH_CALLBACK,
            'oauth_signature_method' => $xro_settings['signature_method']),
        'signatures'=> $signatures));

    // The above object generates a simple URL that includes a signature, the 
    // needed parameters, and the web page that will handle our request.  I now
    // "load" that web page into a string variable.
    $ch = curl_init();
    
	curl_setopt_array($ch, $options);

    if(isset($_GET['debug'])){
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
    // Step 3: Exchange the Authorized Request Token for an
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
	curl_setopt_array($ch, $options);
	curl_setopt($ch, CURLOPT_URL, $result['signed_url']);
	$r = curl_exec($ch);

	// Voila, we've got an access token.
	parse_str($r, $returned_items);		   
	$access_token = $returned_items['oauth_token'];
	$access_token_secret = $returned_items['oauth_token_secret'];
	$oauth_session_handle = $returned_items['oauth_session_handle'];
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
    $signatures['oauth_session_handle'] = $oauth_session_handle;
    //////////////////////////////////////////////////////////////////////
    
    // Example Xero API Access:
    // This will build a link to an RSS feed of the users calendars.
    $oauthObject->reset();
    $result = $oauthObject->sign(array(
        'path'      => $xro_settings['xero_url'].'/Organisation/',
        //'parameters'=> array('Where' => 'Type%3d%3d%22BANK%22'),
        'parameters'=> array(
			'oauth_signature_method' => $xro_settings['signature_method']),
        'signatures'=> $signatures));

    // Instead of going to the list, I will just print the link along with the 
    // access token and secret, so we can play with it in the sandbox:
    // http://googlecodesamples.com/oauth_playground/
    //
    $ch = curl_init();
	curl_setopt_array($ch, $options);
    curl_setopt($ch, CURLOPT_URL, $result['signed_url']);
	$r = curl_exec($ch);
    echo "REQ URL" . $result['signed_url'];
    // start a session to show how we could use this in an app
    session_start();
    $_SESSION['access_token'] = $access_token;
	$_SESSION['access_token_secret']   = $access_token_secret;
	$_SESSION['oauth_session_handle']   = $oauth_session_handle;
	$_SESSION['time']     = time();

    $output = "<p>Access Token: ". $_SESSION['access_token'] ."<BR>
                  Token Secret: ". $_SESSION['access_token_secret'] . "<BR>
                  Session Handle: ". $_SESSION['oauth_session_handle'] ."</p>
               <p><a href=''>GET Accounts</a></p>";
               echo 'CURL RESULT: <textarea cols="160" rows="40">' . $r . '</textarea><br/>';
    curl_close($ch);
}     

}
?>
<HTML>
<BODY>
<a href="<?php echo $_SERVER['PHP_SELF'] . SID ?>?endpoint=Accounts&start=1">Accounts</a><br/>
<a href="<?php echo $_SERVER['PHP_SELF'] . SID ?>?endpoint=Organisation&start=1">Organisation</a><br/>
<a href="<?php echo $_SERVER['PHP_SELF'] . SID ?>?endpoint=Invoices&start=1">Invoices</a><br/>
<a href="<?php echo $_SERVER['PHP_SELF'] . SID ?>?endpoint=Contacts&start=1">Contacts</a><br/>
<a href="<?php echo $_SERVER['PHP_SELF'] . SID ?>?endpoint=Currencies&start=1">Currencies</a><br/>
<a href="<?php echo $_SERVER['PHP_SELF'] . SID ?>?endpoint=TrackingCategories&start=1">TrackingCategories</a><br/>
<a href="<?php echo $_SERVER['PHP_SELF'] . SID ?>?endpoint=Journals&start=1">Journals</a><br/>
<a href="<?php echo $_SERVER['PHP_SELF'] . SID ?>?action=ChangeToken&start=1">Token Refresh</a><br/>
</BODY>
</HTML>
