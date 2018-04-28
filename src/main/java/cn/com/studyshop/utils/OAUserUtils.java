package cn.com.studyshop.utils;

import java.util.ArrayList;
import java.util.List;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.Session;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;

import cn.com.studyshop.constant.ConstantInterf;
import cn.com.studyshop.entity.User;
import cn.com.studyshop.oauth2.entity.OAuthUser;

/**
 * 
 * UPDATED BY LIU
 *
 */
public class OAUserUtils {

	public static User getCurrUser() {
		Session session = SecurityUtils.getSubject().getSession();

		Gson gson = new Gson();
		String oAuthUserJson = gson.toJson(session.getAttribute(ConstantInterf.USER_INFO));
		ObjectMapper mapper = new ObjectMapper();
		OAuthUser oAUser = null;
		try {
			oAUser = mapper.readValue(oAuthUserJson, OAuthUser.class);
		} catch (Exception e) {
			// doNothing
		}
		User user = oAUser.getUser();
		return user;
	}

	/**
	 * 获取OAuthUser
	 * 
	 * @return
	 */
	public static OAuthUser getOAuthUser() {
		Session session = SecurityUtils.getSubject().getSession();

		Gson gson = new Gson();
		String oAuthUserJson = gson.toJson(session.getAttribute(ConstantInterf.USER_INFO));
		ObjectMapper mapper = new ObjectMapper();
		OAuthUser oAUser = null;
		try {
			oAUser = mapper.readValue(oAuthUserJson, OAuthUser.class);
		} catch (Exception e) {
			// doNothing
		}
		return oAUser;
	}

	/**
	 * 获取组织code
	 * 
	 * @return
	 */
	public static String getOrganizationCode() {
		Session session = SecurityUtils.getSubject().getSession();

		Gson gson = new Gson();
		String oAuthUserJson = gson.toJson(session.getAttribute(ConstantInterf.USER_INFO));
		ObjectMapper mapper = new ObjectMapper();
		OAuthUser oAUser = null;
		try {
			oAUser = mapper.readValue(oAuthUserJson, OAuthUser.class);
		} catch (Exception e) {
			// doNothing
		}
		User user = oAUser.getUser();
		return user.getReserve();
	}

	/**
	 * 获取该用户管理的所有货主列表
	 * 
	 * @return
	 */
	public static List<String> getOwnerList() {
		List<String> ownerList = new ArrayList<>();
		Session session = SecurityUtils.getSubject().getSession();
		Gson gson = new Gson();
		String oAuthUserJson = gson.toJson(session.getAttribute(ConstantInterf.USER_INFO));
		ObjectMapper mapper = new ObjectMapper();
		OAuthUser oAUser = null;
		try {
			oAUser = mapper.readValue(oAuthUserJson, OAuthUser.class);
		} catch (Exception e) {
			// doNothing
		}
		oAUser.getOwnerlist().forEach(o -> ownerList.add(o.getOwner()));
		return ownerList;
	}

	/**
	 * 获取该用户管理的所有角色列表
	 * 
	 * @return
	 */
	public static List<String> getRoleList() {
		List<String> roleList = new ArrayList<>();
		Session session = SecurityUtils.getSubject().getSession();
		Gson gson = new Gson();
		String oAuthUserJson = gson.toJson(session.getAttribute(ConstantInterf.USER_INFO));
		ObjectMapper mapper = new ObjectMapper();
		OAuthUser oAUser = null;
		try {
			oAUser = mapper.readValue(oAuthUserJson, OAuthUser.class);
		} catch (Exception e) {
			// doNothing
		}
		oAUser.getRolelist().forEach(o -> roleList.add(o.getRolecode()));
		return roleList;
	}
}
