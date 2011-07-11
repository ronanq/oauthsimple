<?php

// file includes
define('BASE_PATH',realpath('.'));

// different app method defaults
$xro_defaults = array( 'xero_url'     => 'https://api.xero.com/api.xro/2.0',
                     'site'    => 'https://api.xero.com',
                     'authorize_url'    => 'https://api.xero.com/oauth/Authorize',
                     'signature_method'    => 'HMAC-SHA1');
                     
$xro_private_defaults = array( 'xero_url'     => 'https://api.xero.com/api.xro/2.0',
                     'site'    => 'https://api.xero.com',
                     'authorize_url'    => 'https://api.xero.com/oauth/Authorize',
                     'signature_method'    => 'RSA-SHA1');
                     
$xro_partner_defaults = array( 'xero_url'     => 'https://api-partner.network.xero.com/api.xro/2.0',
                     'site'    => 'https://api-partner.network.xero.com',
                     'authorize_url'    => 'https://api.xero.com/oauth/Authorize',
                     'signature_method'    => 'RSA-SHA1');
                     
$xro_partner_mac_defaults = array( 'xero_url'     => 'https://api-partner2.network.xero.com/api.xro/2.0',
                     'site'    => 'https://api-partner2.network.xero.com',
                     'authorize_url'    => 'https://api.xero.com/oauth/Authorize',
                     'signature_method'    => 'RSA-SHA1');
                     
// standard Xero OAuth stuff
$xro_consumer_options = array( 'request_token_path'    => '/oauth/RequestToken',
                     'access_token_path'    => '/oauth/AccessToken',
                     'authorize_path'    => '/oauth/Authorize');
                     