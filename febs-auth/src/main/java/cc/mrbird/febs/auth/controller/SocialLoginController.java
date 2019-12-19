package cc.mrbird.febs.auth.controller;

import cc.mrbird.febs.auth.entity.BindUser;
import cc.mrbird.febs.auth.entity.UserConnection;
import cc.mrbird.febs.auth.service.SocialLoginService;
import cc.mrbird.febs.common.entity.FebsResponse;
import cc.mrbird.febs.common.exception.FebsException;
import cc.mrbird.febs.common.utils.FebsUtil;
import lombok.extern.slf4j.Slf4j;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.request.AuthRequest;
import me.zhyd.oauth.utils.AuthStateUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import java.io.IOException;
import java.util.List;

/**
 * @author MrBird
 */
@Slf4j
@Controller
@RequestMapping("social")
public class SocialLoginController {

    private static final String TYPE_LOGIN = "login";
    private static final String TYPE_BIND = "bind";

    @Autowired
    private SocialLoginService socialLoginService;
    @Value("${febs.frontUrl}")
    private String frontUrl;


    //https://apicloud.mrbird.cn:8301/auth/social/login/github/login
    /**
     * 登录 1.返回第三方登录页面
     *
     * @param oauthType 第三方登录类型
     * @param response  response
     */
    @ResponseBody
    @GetMapping("/login/{oauthType}/{type}")
    public void renderAuth(@PathVariable String oauthType, @PathVariable String type, HttpServletResponse response) throws IOException, FebsException {
        AuthRequest authRequest = socialLoginService.renderAuth(oauthType);
        response.sendRedirect(authRequest.authorize(oauthType + "::" + AuthStateUtils.createState()) + "::" + type);
    }

    /**
     * 登录成功后的回调 2.第三方登录确认后，返回code,在获取第三方的用户信息，判断在系统中是否有用户信息然后再进行OAuth登录
     *
     * https://apicloud.mrbird.cn:8301/auth/social/gitee/callback
     *
     * code: 16d43bef3155465f0de6ccb9b0cd7723e149405bbf0f1235ca0168d0f1da3f0a
     * state: gitee::46f5ae4547e7df06cb0797ee70c77f13::login
     *
     * https://apicloud.mrbird.cn:8301/auth/social/qq/callback?
     * code=7F70FC4ECA24C6F8B90B3A77C6E51BD2&
     * state=qq%3A%3A6b8caea09d743683745d3e105f7fe024%3A%3Abind
     *
     * @param oauthType 第三方登录类型
     * @param callback  携带返回的信息
     * @return String
     */
    @GetMapping("/{oauthType}/callback")
    public String login(@PathVariable String oauthType, AuthCallback callback, String state, Model model) {
        try {
            FebsResponse febsResponse = null;
            String type = StringUtils.substringAfterLast(state, "::");
            if (StringUtils.equals(type, TYPE_BIND)) {
                febsResponse = socialLoginService.resolveBind(oauthType, callback);
            } else {
                febsResponse = socialLoginService.resolveLogin(oauthType, callback);
            }
            model.addAttribute("response", febsResponse);
            model.addAttribute("frontUrl", frontUrl);
            return "result";
        } catch (Exception e) {
            String errorMessage = FebsUtil.containChinese(e.getMessage()) ? e.getMessage() : "第三方登录失败";
            model.addAttribute("error", e.getMessage());
            return "error";
        }
    }

    /**
     * 绑定并登录
     *
     * bindUsername: xiaotong
     * bindPassword: hao15071392583
     * uuid: 2215843
     * username: tong-jian
     * nickname: 小童
     * avatar: https://gitee.com/assets/no_portrait.png
     * gender: UNKNOWN
     * source: GITEE
     *
     * @param bindUser bindUser
     * @param authUser authUser
     * @return FebsResponse
     */
    @ResponseBody
    @PostMapping("bind/login")
    public FebsResponse bindLogin(@Valid BindUser bindUser, AuthUser authUser) throws FebsException {
        OAuth2AccessToken oAuth2AccessToken = this.socialLoginService.bindLogin(bindUser, authUser);
        return new FebsResponse().data(oAuth2AccessToken);
    }

    /**
     * 注册并登录
     *
     * 第三方登录成功后-->返回
     *
     *
     * bindUsername=1245&
     * bindPassword=123456&
     * uuid=46390960&
     * username=xiaotongtj&
     * nickname=Une-orange-charmante%20&
     * avatar=https%3A%2F%2Favatars2.githubusercontent.com%2Fu%2F46390960%3Fv%3D4&
     * blog=&
     * location=wuhan&
     * remark=Une-orange-charmante&
     * gender=UNKNOWN&
     * source=GITHUB&
     */
    @ResponseBody
    @PostMapping("sign/login")
    public FebsResponse signLogin(@Valid BindUser registUser, AuthUser authUser) throws FebsException {
        OAuth2AccessToken oAuth2AccessToken = this.socialLoginService.signLogin(registUser, authUser);
        return new FebsResponse().data(oAuth2AccessToken);
    }

    /**
     * 绑定
     *
     * @param bindUser bindUser
     * @param authUser authUser
     */
    @ResponseBody
    @PostMapping("bind")
    public void bind(BindUser bindUser, AuthUser authUser) throws FebsException {
        this.socialLoginService.bind(bindUser, authUser);
    }

    /**
     * 解绑
     *
     * @param bindUser  bindUser
     * @param oauthType oauthType
     */
    @ResponseBody
    @DeleteMapping("unbind")
    public void unbind(BindUser bindUser, String oauthType) throws FebsException {
        this.socialLoginService.unbind(bindUser, oauthType);
    }

    /**
     * 根据用户名获取绑定关系
     *
     * @param username 用户名
     * @return FebsResponse
     */
    @ResponseBody
    @GetMapping("connections/{username}")
    public FebsResponse findUserConnections(@NotBlank(message = "{required}") @PathVariable String username) {
        List<UserConnection> userConnections = this.socialLoginService.findUserConnections(username);
        return new FebsResponse().data(userConnections);
    }
}
