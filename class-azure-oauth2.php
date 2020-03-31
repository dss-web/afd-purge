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
	private $access_token_url_template  = 'https://login.microsoftonline.com/{tenant}/oauth2/token';

	private $authorization_url;
	private $access_token_url;
	private $client_id;
	private $client_secret;
	private $redirect_uri;
	private $scope;
	private $tenant;

	/**
	 * Summary of __construct
	 * @param string $client_id
	 * @param string $client_secret
	 * @param string $redirect_uri
	 * @param string $scope
	 * @param string $tenant
	 * @return void
	 */
	public function __construct( string $client_id, string $client_secret, string $redirect_uri, string $scope, string $tenant = 'common' ) {

		$this->authorization_url = str_replace('{tenant}', $tenant, $this->authorization_url_template);
		$this->access_token_url  = str_replace('{tenant}', $tenant, $this->access_token_url_template);

		$this->client_id     = $client_id;
		$this->client_secret = $client_secret;
		$this->$redirect_uri = $redirect_uri;
		$this->scope         = $scope;
	}

	/**
	 * Get The Authorization Code. It's later used when retrieving the access token.
	 *
	 * @see https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow#request-an-authorization-code
	 *
	 * @return mixed
	 */
	public function get_authorization_code() {
		$args = [
			'method'      => 'GET',
			'httpversion' => '1.1',
			'blocking'    => true,
			'body'        => [
				'client_id'     => $this->client_id,
				'redirect_uri'  => $this->$redirect_uri,
				'scope'         => $scope,
				'response_type' => 'code',
				'state'         => wp_create_nonce('afd-purge'),
			],
		];

		add_filter('https_ssl_verify', '__return_false');
		$request = wp_remote_request(
			$this->$authorization_url, $this->request_args(
				[
					'response_type' => 'code',
					'state'         => wp_create_nonce('afd-purge'),
				]
			)
		);

		if ( is_wp_error($request) ) {
			return false; //TODO: Throw Exception ?
		}

		$response = json_decode(wp_remote_retrieve_body($request));

		if ( true === $response['admin_consent'] && wp_verify_nonce('afd-purge', $response['state']) ) {
			return $response['code'];
		} else {
			return false;
		}
	}

	/**
	 * Summary of get_access_token
	 *
	 * @see https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow#request-an-access-token
	 *
	 * @param string $authorization_code
	 * @return mixed
	 */
	public function get_access_token( string $authorization_code ) {

		add_filter('https_ssl_verify', '__return_false');
		$request = wp_remote_request(
			$this->$access_token_url, $this->request_args(
				[
					'code'       => $authorization_code,
					'grant_type' => 'authorization_code',
				]
			)
		);

		if ( is_wp_error($request) ) {
			return false; // TODO: Throw Exception ?
		}

		return json_decode(wp_remote_retrieve_body($request));

	}


	/**
	 * Summary of refresh_access_token
	 *
	 * @see https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow#refresh-the-access-token
	 *
	 * @param string $token
	 * @return void
	 */
	public function refresh_access_token( string $refresh_token ) {
		add_filter('https_ssl_verify', '__return_false');
		$request = wp_remote_request(
			$this->$access_token_url, $this->request_args(
				[
					'refresh_token' => $refresh_token,
					'grant_type'    => 'refresh_token',
				]
			)
		);

		if ( is_wp_error($request) ) {
			return false; // TODO: Throw Exception ?
		}

		return json_decode(wp_remote_retrieve_body($request));
	}

	/**
	 * Build request args array
	 *
	 * @param array $extra_args
	 * @return array
	 */
	private function request_args( array $extra_args ) : array {
		$body = [
			'client_id'     => $this->client_id,
			'client_secret' => $this->client_secret,
			'redirect_uri'  => $this->$redirect_uri,
			'scope'         => $this->scope,
		];
		return [
			'method'      => 'POST',
			'httpversion' => '1.1',
			'blocking'    => true,
			'body'        => $body + $extra_args,
		];
	}
}
