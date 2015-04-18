/**
 * $Id$
 *
 * Copyright (C) 2010 CSBI. All Rights Reserved
 */
package ru.app.server.controllers;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.util.JSONPObject;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.web.bind.annotation.RequestMethod.*;


/**
 * @author p.pavlovsky
 * @version $Revision$
 *          Controller for processing requests
 */
@Controller
public class UserController {
    private static final Logger log = Logger.getLogger(UserController.class);


    /**
     * Using map to find user messages
     */
    private static final Map<String, String> USER_MESSAGES_MAP = new HashMap<>();

    static {
        USER_MESSAGES_MAP.put("user", "Welcome user!");
        USER_MESSAGES_MAP.put("admin", "Hail to the king!");
        USER_MESSAGES_MAP.put("other", "User other does not have access");
    }

    /**
     * Request count param to save in session
     */
    public static final String REQUESTS_COUNT_PARAM = "requestsCount";


    /**
     * Main request method
     *
     * @param request  request
     * @param response response
     * @return json response
     */
    @RequestMapping(value = "/", method = {GET}, produces = "application/json")
    @ResponseBody
    public String getMethod(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession();

        ObjectMapper mapper = new ObjectMapper();
        Object obj = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        User user = (User) obj;
        String userName = user.getUsername();
        Integer requests = (Integer) session.getAttribute(REQUESTS_COUNT_PARAM);

        if (requests == null) {
            requests = 1;
            session.setAttribute(REQUESTS_COUNT_PARAM, requests);
        } else {
            requests = requests + 1;
            session.setAttribute(REQUESTS_COUNT_PARAM, requests);
        }

        if (userName.equals("other")) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        }
        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("message", USER_MESSAGES_MAP.get(userName));
        resultMap.put("count", requests);

        String result = null;
        try {
            result = mapper.writeValueAsString(resultMap);
        } catch (IOException e) {
            //mapper method must work well.
            throw new RuntimeException(e);
        }
        return result;

    }

    /**
     * Request not allowerd methods
     *
     * @param request  request
     * @param response response
     * @return json response
     * @throws Exception
     */
    @RequestMapping(value = "/data", method = {GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, TRACE}, produces = "application/json")
    @ResponseBody
    public String otherMethod(HttpServletRequest request, HttpServletResponse response) {
        ObjectMapper mapper = new ObjectMapper();
        Map<String, String> result = new HashMap<String, String>();
        result.put("message", "Method not supported");

        response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);

        String resultJson = null;
        try {
            resultJson = mapper.writeValueAsString(result);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return resultJson;
    }


}