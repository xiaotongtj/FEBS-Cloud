package cc.mrbird.febs.auth.service.impl;

import cc.mrbird.febs.auth.entity.BindUser;
import cc.mrbird.febs.auth.entity.UserConnection;
import cc.mrbird.febs.auth.manager.UserManager;
import cc.mrbird.febs.auth.properties.FebsAuthProperties;
import cc.mrbird.febs.auth.service.SocialLoginService;
import cc.mrbird.febs.auth.service.UserConnectionService;
import cc.mrbird.febs.common.entity.FebsAuthUser;
import cc.mrbird.febs.common.entity.FebsResponse;
import cc.mrbird.febs.common.entity.constant.GrantTypeConstant;
import cc.mrbird.febs.common.entity.constant.ParamsConstant;
import cc.mrbird.febs.common.entity.constant.SocialConstant;
import cc.mrbird.febs.common.entity.system.SystemUser;
import cc.mrbird.febs.common.exception.FebsException;
import cc.mrbird.febs.common.utils.HttpContextUtil;
import cn.hutool.core.util.StrUtil;
import com.xkcoding.justauth.AuthRequestFactory;
import me.zhyd.oauth.config.AuthSource;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.request.AuthRequest;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.password.ResourceOwnerPasswordTokenGranter;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author MrBird
 */
@Service
public class SocialLoginServiceImpl implements SocialLoginService {

    private static final String USERNAME = "username";
    private static final String PASSWORD = "password";

    private static final String NOT_BIND = "not_bind";
    private static final String SOCIAL_LOGIN_SUCCESS = "social_login_success";

    @Autowired
    private UserManager userManager;
    @Autowired
    private AuthRequestFactory factory;
    @Autowired
    private FebsAuthProperties properties;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private UserConnectionService userConnectionService;
    //oauth的密码模式
    @Autowired
    private ResourceOwnerPasswordTokenGranter granter;
    @Autowired
    private RedisClientDetailsService redisClientDetailsService;

    @Override
    public AuthRequest renderAuth(String oauthType) throws FebsException {
        return factory.get(getAuthSource(oauthType));
    }

    //直接返回第三方的用户数据,用于绑定第三方登录账号
    @Override
    public FebsResponse resolveBind(String oauthType, AuthCallback callback) throws FebsException {
        FebsResponse febsResponse = new FebsResponse();
        AuthRequest authRequest = factory.get(getAuthSource(oauthType));
        AuthResponse<?> response = authRequest.login(resolveAuthCallback(callback));
        if (response.ok()) {
            //第三方登录的用户信息
            febsResponse.data(response.getData());
        } else {
            throw new FebsException(String.format("第三方登录失败，%s", response.getMsg()));
        }
        return febsResponse;
    }

    //回调的时候，判断用户在系统中是否存在，存在就登录该系统的OAuth2系统，并返回OAuth_token
    @Override
    public FebsResponse resolveLogin(String oauthType, AuthCallback callback) throws FebsException {
        FebsResponse febsResponse = new FebsResponse();
        AuthRequest authRequest = factory.get(getAuthSource(oauthType));
        //第三方登录系统的信息
        AuthResponse<?> response = authRequest.login(resolveAuthCallback(callback));
        if (response.ok()) {
            AuthUser authUser = (AuthUser) response.getData();
            UserConnection userConnection = userConnectionService.selectByCondition(authUser.getSource().toString(), authUser.getUuid());
            if (userConnection == null) {
                //这里应该是弹窗，提示绑定登录或者注册登录
                febsResponse.message(NOT_BIND).data(authUser);
            } else {
                //第三方登录系统用户名-->UserConnection-->系统用户(本系统)
                SystemUser user = userManager.findByName(userConnection.getUserName());
                if (user == null) {
                    throw new FebsException("系统中未找到与第三方账号对应的账户");
                }
                //这里返回后，就直接进入首页了
                //返回的是本系统的access_token信息(3点)
                OAuth2AccessToken oAuth2AccessToken = getOAuth2AccessToken(user);
                febsResponse.message(SOCIAL_LOGIN_SUCCESS).data(oAuth2AccessToken);
                febsResponse.put(USERNAME, user.getUsername());
            }
        } else {
            throw new FebsException(String.format("第三方登录失败，%s", response.getMsg()));
        }
        return febsResponse;
    }


    /**
     * OAuth2AccessToken
     * {
     *     "data":{
     *         "access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NzcwMTgxOTIsInVzZXJfbmFtZSI6IjEyNDUiLCJhdXRob3JpdGllcyI6WyJtb25pdG9yOnppcGtpbiIsInVzZXI6dmlldyIsIm1vbml0b3I6cmVnaXN0ZXIiLCJkZXB0OmFkZCIsIm1vYml0b3I6YWRtaW4iLCJncmFmYW5hOnZpZXciLCJyb2xlOmFkZCIsInJvbGU6ZXhwb3J0IiwibW9uaXRvcjpzd2FnZ2VyIiwibWVudTpleHBvcnQiLCJkZXB0OmV4cG9ydCIsIm1lbnU6dmlldyIsInJvbGU6dmlldyIsInVzZXI6ZXhwb3J0IiwiZ2VuOmNvbmZpZyIsImNsaWVudDphZGQiLCJkZXB0OnZpZXciLCJtb25pdG9yOmtpYmFuYSIsIm90aGVyczpleGltcG9ydCIsImxvZzp2aWV3IiwiY2xpZW50OnZpZXciLCJnZW46Z2VuZXJhdGU6Z2VuIiwibW9uaXRvcjpsb2dpbmxvZyIsIm1lbnU6YWRkIiwiZ2VuOmdlbmVyYXRlIiwibG9naW5sb2c6ZXhwb3J0IiwiY2xpZW50OmRlY3J5cHQiLCJsb2c6ZXhwb3J0Il0sImp0aSI6IjA2ODJlNWYwLWE2NmYtNDY3Yi1iY2ZkLTI1ZDk2N2VkMWI4NiIsImNsaWVudF9pZCI6ImFwcCIsInNjb3BlIjpbImFsbCIsInRlc3QiXX0.HFjZQs5gAyBt6aSkh-cm6_3CRIRGxRfYtUYHA1xUaY0",
     *         "token_type":"bearer",
     *         "refresh_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiIxMjQ1Iiwic2NvcGUiOlsiYWxsIiwidGVzdCJdLCJhdGkiOiIwNjgyZTVmMC1hNjZmLTQ2N2ItYmNmZC0yNWQ5NjdlZDFiODYiLCJleHAiOjE1ODAyNTgxOTIsImF1dGhvcml0aWVzIjpbIm1vbml0b3I6emlwa2luIiwidXNlcjp2aWV3IiwibW9uaXRvcjpyZWdpc3RlciIsImRlcHQ6YWRkIiwibW9iaXRvcjphZG1pbiIsImdyYWZhbmE6dmlldyIsInJvbGU6YWRkIiwicm9sZTpleHBvcnQiLCJtb25pdG9yOnN3YWdnZXIiLCJtZW51OmV4cG9ydCIsImRlcHQ6ZXhwb3J0IiwibWVudTp2aWV3Iiwicm9sZTp2aWV3IiwidXNlcjpleHBvcnQiLCJnZW46Y29uZmlnIiwiY2xpZW50OmFkZCIsImRlcHQ6dmlldyIsIm1vbml0b3I6a2liYW5hIiwib3RoZXJzOmV4aW1wb3J0IiwibG9nOnZpZXciLCJjbGllbnQ6dmlldyIsImdlbjpnZW5lcmF0ZTpnZW4iLCJtb25pdG9yOmxvZ2lubG9nIiwibWVudTphZGQiLCJnZW46Z2VuZXJhdGUiLCJsb2dpbmxvZzpleHBvcnQiLCJjbGllbnQ6ZGVjcnlwdCIsImxvZzpleHBvcnQiXSwianRpIjoiYTRmNDc2OTUtZDIzMS00NTEwLTg1MzEtNzNhYmFhZjZlODQ1IiwiY2xpZW50X2lkIjoiYXBwIn0.RmmCRKkY5Ak322471aArxf6lbem-vocOJWta38T7Weg",
     *         "expires_in":359999,
     *         "scope":"all test",
     *         "jti":"0682e5f0-a66f-467b-bcfd-25d967ed1b86"
     *     }
     * }
     * @param bindUser 绑定用户
     * @param authUser 第三方平台对象
     * @return
     * @throws FebsException
     */
    @Override
    public OAuth2AccessToken bindLogin(BindUser bindUser, AuthUser authUser) throws FebsException {
        SystemUser systemUser = userManager.findByName(bindUser.getBindUsername());
        if (systemUser == null || !passwordEncoder.matches(bindUser.getBindPassword(), systemUser.getPassword())) {
            throw new FebsException("绑定系统账号失败，用户名或密码错误！");
        }
        this.createConnection(systemUser, authUser);
        return this.getOAuth2AccessToken(systemUser);
    }

    @Override
    public OAuth2AccessToken signLogin(BindUser registUser, AuthUser authUser) throws FebsException {
        SystemUser user = this.userManager.findByName(registUser.getBindUsername());
        if (user != null) {
            throw new FebsException("该用户名已存在！");
        }
        String encryptPassword = passwordEncoder.encode(registUser.getBindPassword());
        SystemUser systemUser = this.userManager.registUser(registUser.getBindUsername(), encryptPassword);
        this.createConnection(systemUser, authUser);
        return this.getOAuth2AccessToken(systemUser);
    }

    @Override
    public void bind(BindUser bindUser, AuthUser authUser) throws FebsException {
        String username = bindUser.getBindUsername();
        if (isCurrentUser(username)) {
            UserConnection userConnection = userConnectionService.selectByCondition(authUser.getSource().toString(), authUser.getUuid());
            if (userConnection != null) {
                throw new FebsException("绑定失败，该第三方账号已绑定" + userConnection.getUserName() + "系统账户");
            }
            SystemUser systemUser = new SystemUser();
            systemUser.setUsername(username);
            this.createConnection(systemUser, authUser);
        } else {
            throw new FebsException("绑定失败，您无权绑定别人的账号");
        }
    }

    @Override
    public void unbind(BindUser bindUser, String oauthType) throws FebsException {
        String username = bindUser.getBindUsername();
        if (isCurrentUser(username)) {
            this.userConnectionService.deleteByCondition(username, oauthType);
        } else {
            throw new FebsException("绑定失败，您无权解绑别人的账号");
        }
    }

    @Override
    public List<UserConnection> findUserConnections(String username) {
        return this.userConnectionService.selectByCondition(username);
    }

    private void createConnection(SystemUser systemUser, AuthUser authUser) {
        UserConnection userConnection = new UserConnection();
        userConnection.setUserName(systemUser.getUsername());
        userConnection.setProviderName(authUser.getSource().toString());
        userConnection.setProviderUserId(authUser.getUuid());
        userConnection.setProviderUserName(authUser.getUsername());
        userConnection.setImageUrl(authUser.getAvatar());
        userConnection.setNickName(authUser.getNickname());
        userConnection.setLocation(authUser.getLocation());
        this.userConnectionService.createUserConnection(userConnection);
    }

    private AuthCallback resolveAuthCallback(AuthCallback callback) {
        String state = callback.getState();
        String[] strings = StringUtils.splitByWholeSeparatorPreserveAllTokens(state, "::");
        if (strings.length == 3) {
            callback.setState(strings[0] + "::" + strings[1]);
        }
        return callback;
    }

    private AuthSource getAuthSource(String type) throws FebsException {
        if (StrUtil.isNotBlank(type)) {
            return AuthSource.valueOf(type.toUpperCase());
        } else {
            throw new FebsException(String.format("暂不支持%s第三方登录", type));
        }
    }

    private boolean isCurrentUser(String username) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        FebsAuthUser authUser = (FebsAuthUser) authentication.getPrincipal();
        return StringUtils.equalsIgnoreCase(username, authUser.getUsername());
    }

    //内置的系统用户
    private OAuth2AccessToken getOAuth2AccessToken(SystemUser user) throws FebsException {
        final HttpServletRequest httpServletRequest = HttpContextUtil.getHttpServletRequest();
        httpServletRequest.setAttribute(ParamsConstant.LOGIN_TYPE, SocialConstant.SOCIAL_LOGIN);
        String socialLoginClientId = properties.getSocialLoginClientId();
        ClientDetails clientDetails = null;
        try {
            //这里是微服务的概念，系统中有其他的子服务
            clientDetails = redisClientDetailsService.loadClientByClientId(socialLoginClientId);
        } catch (Exception e) {
            throw new FebsException("获取第三方登录可用的Client失败");
        }
        if (clientDetails == null) {
            throw new FebsException("未找到第三方登录可用的Client");
        }
        Map<String, String> requestParameters = new HashMap<>(5);
        requestParameters.put(ParamsConstant.GRANT_TYPE, GrantTypeConstant.PASSWORD);
        requestParameters.put(USERNAME, user.getUsername());
        requestParameters.put(PASSWORD, SocialConstant.SOCIAL_LOGIN_PASSWORD);

        String grantTypes = String.join(",", clientDetails.getAuthorizedGrantTypes());
        TokenRequest tokenRequest = new TokenRequest(requestParameters, clientDetails.getClientId(), clientDetails.getScope(), grantTypes);
        //todo 第三方登录后-->获取系统对应的用户-->通过密码模式登录oAuth系统
        return granter.grant(GrantTypeConstant.PASSWORD, tokenRequest);
    }
}
