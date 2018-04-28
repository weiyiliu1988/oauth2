package cn.com.studyshop.realm;

import org.apache.shiro.authc.AuthenticationToken;

/**
 * token封装
 * 
 * @author LIU
 *
 */
public class OAuth2Token implements AuthenticationToken {

	private static final long serialVersionUID = 1L;

	public OAuth2Token(String authCode) {
		this.authCode = authCode;
	}

	public OAuth2Token(String authCode, String principal, String clientId, String clientSecret, String accessTokenURI,
			String userInfoURI, String redirectURI, String oauth_js_id, String userName) {
		super();
		this.userName = userName;
		this.authCode = authCode;
		this.principal = principal;
		this.clientId = clientId;
		this.clientSecret = clientSecret;
		this.accessTokenURI = accessTokenURI;
		this.userInfoURI = userInfoURI;
		this.redirectURI = redirectURI;
		this.oauth_js_id = oauth_js_id;
	}

	private String userName;
	private String authCode; // 授权码
	private String principal;

	// 封装用 for VUE Client
	private String clientId;
	private String clientSecret;
	private String accessTokenURI;
	private String userInfoURI;
	private String redirectURI;

	private String oauth_js_id;

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getOauth_js_id() {
		return oauth_js_id;
	}

	public void setOauth_js_id(String oauth_js_id) {
		this.oauth_js_id = oauth_js_id;
	}

	public static long getSerialversionuid() {
		return serialVersionUID;
	}

	public String getAuthCode() {
		return authCode;
	}

	public void setAuthCode(String authCode) {
		this.authCode = authCode;
	}

	public String getPrincipal() {
		return principal;
	}

	public void setPrincipal(String principal) {
		this.principal = principal;
	}

	@Override
	public Object getCredentials() {
		return authCode;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public String getAccessTokenURI() {
		return accessTokenURI;
	}

	public void setAccessTokenURI(String accessTokenURI) {
		this.accessTokenURI = accessTokenURI;
	}

	public String getUserInfoURI() {
		return userInfoURI;
	}

	public void setUserInfoURI(String userInfoURI) {
		this.userInfoURI = userInfoURI;
	}

	public String getRedirectURI() {
		return redirectURI;
	}

	public void setRedirectURI(String redirectURI) {
		this.redirectURI = redirectURI;
	}

}
