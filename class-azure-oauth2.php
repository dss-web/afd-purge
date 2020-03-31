<?php declare( strict_types = 1 );

 /**
  * Summary of namespace Soderlind\Azure\Oauth2
  *
  * @see https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow
  */

namespace Soderlind\Azure\Oauth2;

interface Azure_Oauth2_Interface {
	public function get_authorization_code();
	public function get_access_token();
}

class Azure_Outh2  implements Azure_Oauth2_Interface {
	private $authorization_url_template = 'https://login.microsoftonline.com/{tenant}/oauth2/authorize';
	private $access_token_url_template     = 'https://login.microsoftonline.com/{tenant}/oauth2/token';

	private $authorization_url;
	private $access_token_url;
	private $client_id;
	private $client_secret;
	private $redirect_uri;
	private $tenant;

	public function __construct( string $client_id, string $client_secret, string $redirect_uri, string $tenant = 'common' ) {

		$this->authorization_url = str_replace('{tenant}', $tenant, $this->authorization_url_template);
		$this->access_token_url = str_replace('{tenant}', $tenant, $this->access_token_url_template);

		$this->client_id     = $client_id;
		$this->client_secret = $client_secret;
		$this->$redirect_uri = $redirect_uri;
	}

	public function get_authorization_code() {
		$args = [
			'method'      => 'GET',
			'httpversion' => '1.1',
			'blocking'    => true,
			'body'        => [
				'client_id'     => $this->client_id,
				'redirect_uri'  => $this->$redirect_uri,
				'response_type' => 'code',
				'state'         => wp_create_nonce('afd-purge'),
			],
		];

		add_filter('https_ssl_verify', '__return_false');
		$response = wp_remote_post($this->$authorization_url, $args);

		$keys = json_decode($response['body']);

		if ( true === $keys['admin_consent'] && wp_verify_nonce('afd-purge', $keys['state']) ) {
			return $keys['code'];
		} else {
			return false;
		}
	}


	public function get_access_token( $code ) {
		$args = [
			'method'      => 'POST',
			'httpversion' => '1.1',
			'blocking'    => true,
			'body'        => [
				'client_id'     => $this->client_id,
				'client_secret' => $this->client_secret,
				'redirect_uri'  => $this->$redirect_uri,
				'code'          => $code,
				'grant_type'    => 'authorization_code',
			],
		];

		add_filter('https_ssl_verify', '__return_false');
		$response = wp_remote_post($this->$access_token_url, $args);

		$keys = json_decode($response['body']);


	}
}
