<?php
require 'vendor/autoload.php';

use \Firebase\JWT\JWT;
use \Firebase\JWT\Key;

define('JWT_AUTH_SECRET_KEY', 'DVm _]o-0%64W}8)8t35*qym=ktJ`GP8lZ vu[in|+i(s xM$faqt&9H3H:iiKfj');

add_action('rest_api_init', function () {

    register_rest_route('twentytwentyfour/v1', '/generate-tokens', array(
        'methods' => 'POST', 
        'callback' => 'generate_tokens_endpoint',
    ));
    
    register_rest_route('twentytwentyfour/v1', '/refresh-tokens', array(
        'methods' => 'POST',
        'callback' => 'refresh_tokens_endpoint',
    ));
    
    register_rest_route('twentytwentyfour/v1', '/validate-token', array(
        'methods' => 'POST',
        'callback' => 'validate_token_endpoint',
    ));
    
    register_rest_route('twentytwentyfour/v1', '/upload-media', array(
        'methods' => 'POST',
        'callback' => 'handle_custom_media_upload',
        'permission_callback' => function () {
            return current_user_can('upload_files');
        }
    ));
});



function generate_tokens_endpoint(WP_REST_Request $request) {
    // $creds = [
    //     'user_login' => $request->get_param('username'),
    //     'user_password' => $request->get_param('password'),
    //     'remember' => true
    // ];

    // $user = wp_signon($creds);

    // if (is_wp_error($user)) {
    //     return new WP_REST_Response(array('error' => 'Invalid username or password'), 403);
    // }

    // $user_data = get_userdata($user->ID);

    // if (!$user_data) {
    //     return new WP_REST_Response(array('error' => 'Failed to retrieve user data'), 500);
    // }

    // $user_id = $user->ID;
    // $user_email = $user_data->user_email; 

    // $tokens = generate_jwt_tokens($user_id, $user_email);

	$tokens = generate_jwt_tokens();
    if (isset($tokens['error'])) {
        return new WP_REST_Response($tokens, 500);
    }

    return new WP_REST_Response($tokens, 200);
}

function generate_jwt_tokens(/*$user_id, $user_email*/) {

	$keyPair = sodium_crypto_sign_keypair();

	$privateKey = base64_encode(sodium_crypto_sign_secretkey($keyPair));
	$publicKey = base64_encode(sodium_crypto_sign_publickey($keyPair));

    $access_payload = [
        'iss' => get_bloginfo('url'),
        'iat' => time(),
        'exp' => time() + (60 * 60 * 24 * 28), // valid for 28 days
        // 'data' => [
        //     'user_id' => $user_id,
        //     'email' => $user_email
        // ]
    ];

    $refresh_payload = [
        'iss' => get_bloginfo('url'),
        'iat' => time(),
        'exp' => time() + (60 * 60 * 24 * 30), // valid for 30 days
        // 'data' => [
        //     'user_id' => $user_id,
        //     'email' => $user_email
        // ]
    ];

    try {
        $access_token = JWT::encode($access_payload, $privateKey, 'EdDSA');
        $refresh_token = JWT::encode($refresh_payload, $privateKey, 'EdDSA');
    } catch (Exception $e) {
        error_log("Error generating JWT tokens: " . $e->getMessage());
        return array('error' => 'Token generation failed');
    }
    
    return array(
        'access_token' => $access_token,
        'access_token_expiry' => $access_payload['exp'],
        'refresh_token' => $refresh_token,
        'refresh_token_expiry' => $refresh_payload['exp'],
		'public_key' => $publicKey
        // 'user_id' => $user_id,
        // 'email' => $user_email
    );
}

function validate_token_endpoint(WP_REST_Request $request) {
    $token = $request->get_param('token');
	$publicKey = $request->get_param('public_key');

	$validation_result = validate_jwt_token($token, $publicKey);

    if (isset($validation_result['error'])) {
        return new WP_REST_Response($validation_result, 401);
    }

    return new WP_REST_Response($validation_result, 200);
}

function validate_jwt_token($token, $publicKey) {
    try {
        $decoded = JWT::decode($token, new Key($publicKey, 'EdDSA'));
        return (array) $decoded;
    } catch (Exception $e) {
        error_log("Error validating JWT token: " . $e->getMessage());
        return array('error' => 'Token validation failed');
    }
}

function refresh_tokens_endpoint(WP_REST_Request $request) {
    $refresh_token = $request->get_param('refresh_token');
	$publicKey = $request->get_param('public_key');

    $tokens = refresh_jwt_tokens($refresh_token, $publicKey);

    if (isset($tokens['error'])) {
        return new WP_REST_Response($tokens, 500);
    }

    return new WP_REST_Response($tokens, 200);
}

function refresh_jwt_tokens($refresh_token, $publicKey) {
    try {
		$decoded = JWT::decode($refresh_token, new Key($publicKey, 'EdDSA'));
        $decoded_array = (array) $decoded;
        // $user_id = $decoded_array['data']->user_id;
        // $user_email = $decoded_array['data']->email;

        // Generate new tokens
        // return generate_jwt_tokens($user_id, $user_email);
		return generate_jwt_tokens();
    } catch (Exception $e) {
        error_log("Error refreshing JWT tokens: " . $e->getMessage());
        return array('error' => 'Token refresh failed');
    }
}

