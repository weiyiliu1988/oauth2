package cn.com.studyshop.filter;

import java.io.IOException;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.oltu.oauth2.common.OAuth;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;

import cn.com.studyshop.constant.ConstantInterf;
import cn.com.studyshop.oauth2.entity.OAuthUser;
import cn.com.studyshop.realm.OAuth2Token;

/**
 * 校验前置过滤(shiroFilter利用)
 * 
 * @author LIU
 *
 */
public class OAuth2AuthenticationFilter extends AuthenticatingFilter {

	private Logger logger = LoggerFactory.getLogger(OAuth2AuthenticationFilter.class);

	private String failureUrl = "http://localhost:9001";// error URL

	public void setFailureUrl(String failureUrl) {
		this.failureUrl = failureUrl;
	}

	@Override
	protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {

		HttpServletRequest httpRequest = (HttpServletRequest) request;
		String code = httpRequest.getParameter(OAuth.OAUTH_CODE);
		String userName = httpRequest.getParameter(OAuth.OAUTH_USERNAME);
		// 封装
		String clientId = httpRequest.getParameter(OAuth.OAUTH_CLIENT_ID);
		String clientSecret = httpRequest.getParameter(OAuth.OAUTH_CLIENT_SECRET);
		String accessTokenURI = httpRequest.getParameter(ConstantInterf.ACCESS_TOKEN_URL);
		String userInfoURI = httpRequest.getParameter(ConstantInterf.USER_INFO_URL);
		String redirectURI = httpRequest.getParameter(OAuth.OAUTH_REDIRECT_URI);
		String oauth_js_id = request.getParameter("oauth_js_id");
		return new OAuth2Token(code, "", clientId, clientSecret, accessTokenURI, userInfoURI, redirectURI, oauth_js_id,
				userName);
	}

	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
		return false;
	}

	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		String userName = httpRequest.getParameter(OAuth.OAUTH_USERNAME);
		logger.debug("onAccessDenied-------------->userName:{}", userName);
		String error = request.getParameter("error");
		String errorDescription = request.getParameter("error_description");
		Session session = null;
		boolean rslt = false;
		if (!StringUtils.isEmpty(error)) {// 如果服务端返回了错误
			WebUtils.issueRedirect(request, response,
					failureUrl + "?error=" + error + "error_description=" + errorDescription);
			return rslt;
		}

		try {
			Subject subject1 = SecurityUtils.getSubject();

			session = subject1.getSession();
			logger.debug("OAuth2AuthenticationFilter----->sessionId:" + session.getId());

		} catch (Exception e) {
			e.printStackTrace();
		}

		if (null != session.getAttribute(ConstantInterf.USER_INFO)) {
			Gson gson = new Gson();
			String oAuthUserJson = gson.toJson(session.getAttribute(ConstantInterf.USER_INFO));
			ObjectMapper mapper = new ObjectMapper();
			OAuthUser oAUser = null;
			try {
				oAUser = mapper.readValue(oAuthUserJson, OAuthUser.class);
				if (null != userName && userName.trim().length() > 0
						&& !oAUser.getUser().getUsername().equals(userName)) {
					logger.debug("[OAuth2AuthenticationFilter] session无效化");
					session.setTimeout(0);
					return rslt;
				}
			} catch (Exception e) {
				// doNothing
			}
		}

		Subject subject = getSubject(request, response);

		if (!subject.isAuthenticated()) {
			if (StringUtils.isEmpty(request.getParameter(OAuth.OAUTH_CODE))) {
				// 如果用户没有身份验证，且没有auth code，则重定向到服务端授权
				logger.debug("OAuth2AuthenticationFilter--->saveRequestAndRedirectToLogin");
				saveRequestAndRedirectToLogin(request, response);
				return rslt;
			}
		}
		logger.debug("OAuth2AuthenticationFilter-----> oauth_token 令牌:{}",
				session.getAttribute(OAuth.OAUTH_ACCESS_TOKEN));
		if (null == session.getAttribute(OAuth.OAUTH_ACCESS_TOKEN)) {
			// session未登录 需要登录
			rslt = executeLogin(request, response);
		} else {
			rslt = true;
		}
		return rslt;
	}

	@Override
	protected boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request,
			ServletResponse response) throws Exception {

		if (Boolean.valueOf(request.getParameter("no_redirect"))) {
			// doNothing
		} else {
			issueSuccessRedirect(request, response);
		}
		logger.debug("onLogin success!");
		return true;
	}

	@Override
	protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException ae, ServletRequest request,
			ServletResponse response) {
		Subject subject = getSubject(request, response);

		if (Boolean.valueOf(request.getParameter("no_redirect"))) {
			// doNothing
			subject.getSession().removeAttribute(ConstantInterf.USER_INFO);
			return false;
		}

		if (subject.isAuthenticated() || subject.isRemembered()) {
			try {
				issueSuccessRedirect(request, response);
			} catch (Exception e) {
				e.printStackTrace();
			}
		} else {
			try {
				WebUtils.issueRedirect(request, response, failureUrl);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return false;
	}

}