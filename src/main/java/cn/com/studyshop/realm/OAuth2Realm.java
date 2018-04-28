package cn.com.studyshop.realm;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthBearerClientRequest;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAccessTokenResponse;
import org.apache.oltu.oauth2.client.response.OAuthResourceResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.credential.PasswordService;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;

import com.fasterxml.jackson.databind.ObjectMapper;

import cn.com.studyshop.constant.ConstantInterf;
import cn.com.studyshop.exception.OAuth2AuthenticationException;
import cn.com.studyshop.oauth2.entity.OAuthUser;
import cn.com.studyshop.utils.OAUserUtils;

public class OAuth2Realm extends AuthorizingRealm {

	private Logger logger = LoggerFactory.getLogger(OAuth2Realm.class);

	@Autowired
	public PasswordService passwordService;

	@Override
	public boolean supports(AuthenticationToken token) {
		return token instanceof OAuth2Token;// 表示此Realm只支持OAuth2Token类型
	}

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
		logger.debug("[用户角色设定] 赋予用户角色处理开始!");
		List<String> roleCodeList = OAUserUtils.getRoleList();
		// 用户角色
		roleCodeList.forEach(o -> authorizationInfo.addRole(o));

		return authorizationInfo;
	}

	/**
	 * 验证
	 * 
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		OAuth2Token oAuth2Token = (OAuth2Token) token;
		String username = extractUsername(oAuth2Token); // 通过授权码获取用户信息
		logger.debug("[用户登录认证] 认证处理开始");
		// 直接通过
		SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(username,
				passwordService.encryptPassword(oAuth2Token.getAuthCode()), getName());
		return authenticationInfo;
	}

	private String extractUsername(OAuth2Token token) {

		try {
			OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());

			// 临时senssionID传送
			OAuthClientRequest accessTokenRequest = OAuthClientRequest.tokenLocation(token.getAccessTokenURI())
					.setGrantType(GrantType.AUTHORIZATION_CODE).setClientId(token.getClientId())
					.setClientSecret(token.getClientSecret()).setCode(token.getAuthCode())// 授权码
					.setParameter("oauth_js_id", token.getOauth_js_id()).setRedirectURI(token.getRedirectURI())
					.buildQueryMessage();

			OAuthAccessTokenResponse oAuthResponse = oAuthClient.accessToken(accessTokenRequest, OAuth.HttpMethod.POST);

			String accessToken = oAuthResponse.getAccessToken();
			Session session = SecurityUtils.getSubject().getSession();

			logger.debug("[Oauth2服务] 令牌code获取成功,令牌:{}", accessToken);
			logger.warn("[SessionID] {}", session.getId());
			session.setAttribute(OAuth.OAUTH_ACCESS_TOKEN, accessToken);// token存放

			// 请求保护资源 用户信息
			OAuthClientRequest userInfoRequest = new OAuthBearerClientRequest(token.getUserInfoURI())
					.setAccessToken(accessToken).buildQueryMessage();
			Map<String, String> sessionIdMap = new HashMap<>();
			sessionIdMap.put("oauth_js_id", token.getOauth_js_id());
			sessionIdMap.put("set-cookie", token.getOauth_js_id());
			userInfoRequest.setHeaders(sessionIdMap);

			userInfoRequest.setHeader("oauth_js_id", token.getOauth_js_id());
			OAuthResourceResponse resourceResponse = oAuthClient.resource(userInfoRequest, OAuth.HttpMethod.GET,
					OAuthResourceResponse.class);
			if (resourceResponse.getResponseCode() != HttpStatus.OK.value()) {
				logger.debug("userInfo信息获取异常");
			}
			String oAuthUserJson = resourceResponse.getBody();
			ObjectMapper mapper = new ObjectMapper();
			OAuthUser OAUser = mapper.readValue(oAuthUserJson, OAuthUser.class);
			session.setAttribute(ConstantInterf.USER_INFO, OAUser);// 用户信息存放
			logger.debug("session用户信息存放完了! 用户名:{}", OAUser.getUser().getUsername());
			return OAUser.getUser().getUsername();
		} catch (Exception e) {
			logger.error("token获取失败! 异常Exception{}", e);
			throw new OAuth2AuthenticationException(e);
		}
	}
}
