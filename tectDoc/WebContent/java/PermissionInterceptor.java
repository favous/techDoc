package com.atc.daizhang.system.security.shiro;

import java.io.PrintWriter;
import java.lang.reflect.Method;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import com.alibaba.fastjson.JSON;
import com.atc.daizhang.beans.system.UserInfo;
import com.atc.daizhang.framework.common.utils.StringUtil;
import com.atc.daizhang.framework.rpc.TO.AjaxResult;
import com.atc.daizhang.framework.rpc.TO.Msg;
import com.atc.daizhang.framework.web.context.RequestContext;
import com.atc.daizhang.system.user.facade.YhFacade;

public class PermissionInterceptor extends HandlerInterceptorAdapter {

    private static final String JSON_CONTENT_TYPE = "application/json;charset=UTF-8";

    private String loginUrl = "";

    public String getLoginUrl() {
        return loginUrl;
    }

    public void setLoginUrl(String loginUrl) {
        this.loginUrl = loginUrl;
    }

    @Autowired
    private YhFacade yhFacade;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        if (handler instanceof HandlerMethod) {
            HandlerMethod hm = (HandlerMethod) handler;
            Class<?> clazz = hm.getBeanType();
            Method m = hm.getMethod();
            try {
                if (clazz != null && m != null) {
                    boolean isMethondAnnotation = m.isAnnotationPresent(RequirePermission.class);
                    if (isMethondAnnotation) {
                        RequirePermission annotation = ((HandlerMethod) handler)
                                .getMethodAnnotation(RequirePermission.class);
                        String zybm = annotation.zybm();
                        boolean isYw = annotation.isYw();
                        int level=annotation.level();
                        if (!StringUtil.isEmpty(zybm)) {
                            UserInfo userInfo = ShiroUtil.getUserInfo();
                            if (userInfo != null) {
                                if (isYw) {
                                    String qyid = request.getParameter("qyid");
                                    if (qyid == null || !yhFacade.checkOperatePermissionForYwJs(zybm,level,
                                            userInfo.getYhid(), Long.parseLong(qyid))) {
                                        compeleteJSONResponse(
                                                new AjaxResult<>().fail().msg(Msg.error("无权限")));
                                        return false;
                                    }
                                } else {
                                    if (!yhFacade.checkOperatePermissionForXtJs(zybm,level, userInfo.getYhid())) {
                                        compeleteJSONResponse(
                                                new AjaxResult<>().fail().msg(Msg.error("无权限")));
                                        return false;
                                    }
                                }
                            } else {

                                compeleteJSONResponse(new AjaxResult<String>().fail()
                                        .execute("top.window.location.href='" + loginUrl+"'"));
                                return false;
                            }

                        }

                    }
                }
            } catch (Exception e) {

            }
        }

        return true;
    }

    /**
     * 
     * 输出JSON类型值到页面端
     * 
     * @param object
     *            [参数说明]
     * 
     * @return void [返回类型说明]
     * @exception throws
     *                [违例类型] [违例说明]
     * @see [类、类#方法、类#成员]
     */
    public void compeleteJSONResponse(Object object) {
        PrintWriter writer = null;
        try {
            RequestContext.getResponse().setContentType(JSON_CONTENT_TYPE);
            writer = RequestContext.getResponse().getWriter();
            String json = JSON.toJSONString(object);
            writer.write(json);
        } catch (Exception e) {

        } finally {
            if (writer != null) {
                writer.flush();
                writer.close();
            }
        }

    }
}