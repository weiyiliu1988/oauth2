package cn.com.studyshop.exception;

import org.apache.shiro.authc.AuthenticationException;

/**
 * 异常封装
 * 
 * @author LIU
 *
 */
public class OAuth2AuthenticationException extends AuthenticationException {

	private static final long serialVersionUID = 1L;

	public OAuth2AuthenticationException(Throwable cause) {
		super(cause);
	}
}
